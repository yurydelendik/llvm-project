//===-- DWARFEvaluator.cpp ------------ -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Expression/DWARFEvaluator.h"
#include "lldb/Expression/DWARFExpression.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/Value.h"
#include "lldb/Core/dwarf.h"

#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"

#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/StackFrame.h"

#include "Plugins/SymbolFile/DWARF/DWARFUnit.h"

using namespace lldb;
using namespace lldb_private;

DWARFEvaluator::DWARFEvaluator(const DWARFExpression &dwarf_expression,
                               ExecutionContext *exe_ctx,
                               RegisterContext *reg_ctx,
                               const Value *initial_value_ptr,
                               const Value *object_address_ptr)
    : m_dwarf_expression(dwarf_expression), m_exe_ctx(exe_ctx),
      m_reg_ctx(reg_ctx), m_initial_value_ptr(initial_value_ptr),
      m_object_address_ptr(object_address_ptr) {}

static bool ReadRegisterValueAsScalar(RegisterContext *reg_ctx,
                                      lldb::RegisterKind reg_kind,
                                      uint32_t reg_num, Status *error_ptr,
                                      Value &value) {
  if (reg_ctx == nullptr) {
    if (error_ptr)
      error_ptr->SetErrorString("No register context in frame.\n");
  } else {
    uint32_t native_reg =
        reg_ctx->ConvertRegisterKindToRegisterNumber(reg_kind, reg_num);
    if (native_reg == LLDB_INVALID_REGNUM) {
      if (error_ptr)
        error_ptr->SetErrorStringWithFormat("Unable to convert register "
                                            "kind=%u reg_num=%u to a native "
                                            "register number.\n",
                                            reg_kind, reg_num);
    } else {
      const RegisterInfo *reg_info =
          reg_ctx->GetRegisterInfoAtIndex(native_reg);
      RegisterValue reg_value;
      if (reg_ctx->ReadRegister(reg_info, reg_value)) {
        if (reg_value.GetScalarValue(value.GetScalar())) {
          value.SetValueType(Value::eValueTypeScalar);
          value.SetContext(Value::eContextTypeRegisterInfo,
                           const_cast<RegisterInfo *>(reg_info));
          if (error_ptr)
            error_ptr->Clear();
          return true;
        } else {
          // If we get this error, then we need to implement a value buffer in
          // the dwarf expression evaluation function...
          if (error_ptr)
            error_ptr->SetErrorStringWithFormat(
                "register %s can't be converted to a scalar value",
                reg_info->name);
        }
      } else {
        if (error_ptr)
          error_ptr->SetErrorStringWithFormat("register %s is not available",
                                              reg_info->name);
      }
    }
  }
  return false;
}

static bool Evaluate_DW_OP_entry_value(std::vector<Value> &stack,
                                       ExecutionContext *exe_ctx,
                                       RegisterContext *reg_ctx,
                                       const DataExtractor &opcodes,
                                       lldb::offset_t &opcode_offset,
                                       Status *error_ptr, Log *log) {
  // DW_OP_entry_value(sub-expr) describes the location a variable had upon
  // function entry: this variable location is presumed to be optimized out at
  // the current PC value.  The caller of the function may have call site
  // information that describes an alternate location for the variable (e.g. a
  // constant literal, or a spilled stack value) in the parent frame.
  //
  // Example (this is pseudo-code & pseudo-DWARF, but hopefully illustrative):
  //
  //     void child(int &sink, int x) {
  //       ...
  //       /* "x" gets optimized out. */
  //
  //       /* The location of "x" here is: DW_OP_entry_value($reg2). */
  //       ++sink;
  //     }
  //
  //     void parent() {
  //       int sink;
  //
  //       /*
  //        * The callsite information emitted here is:
  //        *
  //        * DW_TAG_call_site
  //        *   DW_AT_return_pc ... (for "child(sink, 123);")
  //        *   DW_TAG_call_site_parameter (for "sink")
  //        *     DW_AT_location   ($reg1)
  //        *     DW_AT_call_value ($SP - 8)
  //        *   DW_TAG_call_site_parameter (for "x")
  //        *     DW_AT_location   ($reg2)
  //        *     DW_AT_call_value ($literal 123)
  //        *
  //        * DW_TAG_call_site
  //        *   DW_AT_return_pc ... (for "child(sink, 456);")
  //        *   ...
  //        */
  //       child(sink, 123);
  //       child(sink, 456);
  //     }
  //
  // When the program stops at "++sink" within `child`, the debugger determines
  // the call site by analyzing the return address. Once the call site is found,
  // the debugger determines which parameter is referenced by DW_OP_entry_value
  // and evaluates the corresponding location for that parameter in `parent`.

  // 1. Find the function which pushed the current frame onto the stack.
  if ((!exe_ctx || !exe_ctx->HasTargetScope()) || !reg_ctx) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no exe/reg context");
    return false;
  }

  StackFrame *current_frame = exe_ctx->GetFramePtr();
  Thread *thread = exe_ctx->GetThreadPtr();
  if (!current_frame || !thread) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no current frame/thread");
    return false;
  }

  Target &target = exe_ctx->GetTargetRef();
  StackFrameSP parent_frame = nullptr;
  addr_t return_pc = LLDB_INVALID_ADDRESS;
  uint32_t current_frame_idx = current_frame->GetFrameIndex();
  uint32_t num_frames = thread->GetStackFrameCount();
  for (uint32_t parent_frame_idx = current_frame_idx + 1;
       parent_frame_idx < num_frames; ++parent_frame_idx) {
    parent_frame = thread->GetStackFrameAtIndex(parent_frame_idx);
    // Require a valid sequence of frames.
    if (!parent_frame)
      break;

    // Record the first valid return address, even if this is an inlined frame,
    // in order to look up the associated call edge in the first non-inlined
    // parent frame.
    if (return_pc == LLDB_INVALID_ADDRESS) {
      return_pc = parent_frame->GetFrameCodeAddress().GetLoadAddress(&target);
      LLDB_LOG(log,
               "Evaluate_DW_OP_entry_value: immediate ancestor with pc = {0:x}",
               return_pc);
    }

    // If we've found an inlined frame, skip it (these have no call site
    // parameters).
    if (parent_frame->IsInlined())
      continue;

    // We've found the first non-inlined parent frame.
    break;
  }
  if (!parent_frame || !parent_frame->GetRegisterContext()) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no parent frame with reg ctx");
    return false;
  }

  Function *parent_func =
      parent_frame->GetSymbolContext(eSymbolContextFunction).function;
  if (!parent_func) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no parent function");
    return false;
  }

  // 2. Find the call edge in the parent function responsible for creating the
  //    current activation.
  Function *current_func =
      current_frame->GetSymbolContext(eSymbolContextFunction).function;
  if (!current_func) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no current function");
    return false;
  }

  CallEdge *call_edge = nullptr;
  ModuleList &modlist = target.GetImages();
  ExecutionContext parent_exe_ctx = *exe_ctx;
  parent_exe_ctx.SetFrameSP(parent_frame);
  if (!parent_frame->IsArtificial()) {
    // If the parent frame is not artificial, the current activation may be
    // produced by an ambiguous tail call. In this case, refuse to proceed.
    call_edge = parent_func->GetCallEdgeForReturnAddress(return_pc, target);
    if (!call_edge) {
      LLDB_LOG(log,
               "Evaluate_DW_OP_entry_value: no call edge for retn-pc = {0:x} "
               "in parent frame {1}",
               return_pc, parent_func->GetName());
      return false;
    }
    Function *callee_func = call_edge->GetCallee(modlist, parent_exe_ctx);
    if (callee_func != current_func) {
      LLDB_LOG(log, "Evaluate_DW_OP_entry_value: ambiguous call sequence, "
                    "can't find real parent frame");
      return false;
    }
  } else {
    // The StackFrameList solver machinery has deduced that an unambiguous tail
    // call sequence that produced the current activation.  The first edge in
    // the parent that points to the current function must be valid.
    for (auto &edge : parent_func->GetTailCallingEdges()) {
      if (edge->GetCallee(modlist, parent_exe_ctx) == current_func) {
        call_edge = edge.get();
        break;
      }
    }
  }
  if (!call_edge) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: no unambiguous edge from parent "
                  "to current function");
    return false;
  }

  // 3. Attempt to locate the DW_OP_entry_value expression in the set of
  //    available call site parameters. If found, evaluate the corresponding
  //    parameter in the context of the parent frame.
  const uint32_t subexpr_len = opcodes.GetULEB128(&opcode_offset);
  const void *subexpr_data = opcodes.GetData(&opcode_offset, subexpr_len);
  if (!subexpr_data) {
    LLDB_LOG(log, "Evaluate_DW_OP_entry_value: subexpr could not be read");
    return false;
  }

  const CallSiteParameter *matched_param = nullptr;
  for (const CallSiteParameter &param : call_edge->GetCallSiteParameters()) {
    DataExtractor param_subexpr_extractor;
    if (!param.LocationInCallee.GetExpressionData(param_subexpr_extractor))
      continue;
    lldb::offset_t param_subexpr_offset = 0;
    const void *param_subexpr_data =
        param_subexpr_extractor.GetData(&param_subexpr_offset, subexpr_len);
    if (!param_subexpr_data ||
        param_subexpr_extractor.BytesLeft(param_subexpr_offset) != 0)
      continue;

    // At this point, the DW_OP_entry_value sub-expression and the callee-side
    // expression in the call site parameter are known to have the same length.
    // Check whether they are equal.
    //
    // Note that an equality check is sufficient: the contents of the
    // DW_OP_entry_value subexpression are only used to identify the right call
    // site parameter in the parent, and do not require any special handling.
    if (memcmp(subexpr_data, param_subexpr_data, subexpr_len) == 0) {
      matched_param = &param;
      break;
    }
  }
  if (!matched_param) {
    LLDB_LOG(log,
             "Evaluate_DW_OP_entry_value: no matching call site param found");
    return false;
  }

  // TODO: Add support for DW_OP_push_object_address within a DW_OP_entry_value
  // subexpresion whenever llvm does.
  Value result;
  const DWARFExpression &param_expr = matched_param->LocationInCaller;
  if (!param_expr.Evaluate(&parent_exe_ctx,
                           parent_frame->GetRegisterContext().get(),
                           /*loclist_base_addr=*/LLDB_INVALID_ADDRESS,
                           /*initial_value_ptr=*/nullptr,
                           /*object_address_ptr=*/nullptr, result, error_ptr)) {
    LLDB_LOG(log,
             "Evaluate_DW_OP_entry_value: call site param evaluation failed");
    return false;
  }

  stack.push_back(result);
  return true;
}

bool DWARFEvaluator::Evaluate(Value &result, Status *error_ptr) {
  DataExtractor opcodes;
  if (!m_dwarf_expression.GetExpressionData(opcodes)) {
    if (error_ptr)
      error_ptr->SetErrorString(
          "no location, value may have been optimized out");
    return false;
  }
  return Evaluate(opcodes, result, error_ptr);
}

bool DWARFEvaluator::Evaluate(const DataExtractor &opcodes, Value &result,
                              Status *error_ptr) {
  if (opcodes.GetByteSize() == 0) {
    if (error_ptr)
      error_ptr->SetErrorString(
          "no location, value may have been optimized out");
    return false;
  }
  std::vector<Value> stack;

  Process *process = nullptr;
  StackFrame *frame = nullptr;

  if (m_exe_ctx) {
    process = m_exe_ctx->GetProcessPtr();
    frame = m_exe_ctx->GetFramePtr();
  }
  if (m_reg_ctx == nullptr && frame)
    m_reg_ctx = frame->GetRegisterContext().get();

  if (m_initial_value_ptr)
    stack.push_back(*m_initial_value_ptr);

  lldb::offset_t offset = 0;

  /// Insertion point for evaluating multi-piece expression.
  uint64_t op_piece_offset = 0;
  Value pieces; // Used for DW_OP_piece

  Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_EXPRESSIONS));

  uint8_t _opcode = 0;

  while (opcodes.ValidOffset(offset)) {
    const lldb::offset_t op_offset = offset;
    const uint8_t op = opcodes.GetU8(&offset);
    _opcode = op;

    if (log && log->GetVerbose()) {
      size_t count = stack.size();
      LLDB_LOGF(log, "Stack before operation has %" PRIu64 " values:",
                (uint64_t)count);
      for (size_t i = 0; i < count; ++i) {
        StreamString new_value;
        new_value.Printf("[%" PRIu64 "]", (uint64_t)i);
        stack[i].Dump(&new_value);
        LLDB_LOGF(log, "  %s", new_value.GetData());
      }
      LLDB_LOGF(log, "0x%8.8" PRIx64 ": %s", op_offset,
                DW_OP_value_to_name(op));
    }

    if (!Evaluate(op, process, frame, stack, opcodes, offset, pieces,
                  op_piece_offset, log, error_ptr))
      return false;
  }

  if (stack.empty()) {
    // Nothing on the stack, check if we created a piece value from DW_OP_piece
    // or DW_OP_bit_piece opcodes
    if (pieces.GetBuffer().GetByteSize())
      result = pieces;
    else {
      if (error_ptr)
        error_ptr->SetErrorString("Stack empty after evaluation.");
      return false;
    }
  } else {
    if (log && log->GetVerbose()) {
      size_t count = stack.size();
      LLDB_LOGF(log, "Stack after operation has %" PRIu64 " values:",
                (uint64_t)count);
      for (size_t i = 0; i < count; ++i) {
        StreamString new_value;
        new_value.Printf("[%" PRIu64 "]", (uint64_t)i);
        stack[i].Dump(&new_value);
        LLDB_LOGF(log, "  %s", new_value.GetData());
      }
    }
    result = stack.back();
  }
  return true; // Return true on success
}

bool DWARFEvaluator::Evaluate(const uint8_t op, Process *process,
                              StackFrame *frame, std::vector<Value> &stack,
                              const DataExtractor &opcodes,
                              lldb::offset_t &offset, Value &pieces,
                              uint64_t &op_piece_offset, Log *log,
                              Status *error_ptr) {
  Value tmp;
  uint32_t reg_num;

  lldb::ModuleSP module_sp = m_dwarf_expression.GetModule();
  const DWARFUnit *dwarf_cu = m_dwarf_expression.GetDWARFCompileUnit();
  const lldb::RegisterKind reg_kind = m_dwarf_expression.GetRegisterKind();

  switch (op) {
  // The DW_OP_addr operation has a single operand that encodes a machine
  // address and whose size is the size of an address on the target machine.
  case DW_OP_addr:
    stack.push_back(Scalar(opcodes.GetAddress(&offset)));
    stack.back().SetValueType(Value::eValueTypeFileAddress);
    // Convert the file address to a load address, so subsequent
    // DWARF operators can operate on it.
    if (frame)
      stack.back().ConvertToLoadAddress(module_sp.get(),
                                        frame->CalculateTarget().get());
    break;

  // The DW_OP_addr_sect_offset4 is used for any location expressions in
  // shared libraries that have a location like:
  //  DW_OP_addr(0x1000)
  // If this address resides in a shared library, then this virtual address
  // won't make sense when it is evaluated in the context of a running
  // process where shared libraries have been slid. To account for this, this
  // new address type where we can store the section pointer and a 4 byte
  // offset.
  //      case DW_OP_addr_sect_offset4:
  //          {
  //              result_type = eResultTypeFileAddress;
  //              lldb::Section *sect = (lldb::Section
  //              *)opcodes.GetMaxU64(&offset, sizeof(void *));
  //              lldb::addr_t sect_offset = opcodes.GetU32(&offset);
  //
  //              Address so_addr (sect, sect_offset);
  //              lldb::addr_t load_addr = so_addr.GetLoadAddress();
  //              if (load_addr != LLDB_INVALID_ADDRESS)
  //              {
  //                  // We successfully resolve a file address to a load
  //                  // address.
  //                  stack.push_back(load_addr);
  //                  break;
  //              }
  //              else
  //              {
  //                  // We were able
  //                  if (error_ptr)
  //                      error_ptr->SetErrorStringWithFormat ("Section %s in
  //                      %s is not currently loaded.\n",
  //                      sect->GetName().AsCString(),
  //                      sect->GetModule()->GetFileSpec().GetFilename().AsCString());
  //                  return false;
  //              }
  //          }
  //          break;

  // OPCODE: DW_OP_deref
  // OPERANDS: none
  // DESCRIPTION: Pops the top stack entry and treats it as an address.
  // The value retrieved from that address is pushed. The size of the data
  // retrieved from the dereferenced address is the size of an address on the
  // target machine.
  case DW_OP_deref: {
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString("Expression stack empty for DW_OP_deref.");
      return false;
    }
    Value::ValueType value_type = stack.back().GetValueType();
    switch (value_type) {
    case Value::eValueTypeHostAddress: {
      void *src = (void *)stack.back().GetScalar().ULongLong();
      intptr_t ptr;
      ::memcpy(&ptr, src, sizeof(void *));
      stack.back().GetScalar() = ptr;
      stack.back().ClearContext();
    } break;
    case Value::eValueTypeFileAddress: {
      auto file_addr = stack.back().GetScalar().ULongLong(LLDB_INVALID_ADDRESS);
      if (!module_sp) {
        if (error_ptr)
          error_ptr->SetErrorString(
              "need module to resolve file address for DW_OP_deref");
        return false;
      }
      Address so_addr;
      if (!module_sp->ResolveFileAddress(file_addr, so_addr)) {
        if (error_ptr)
          error_ptr->SetErrorString("failed to resolve file address in module");
        return false;
      }
      addr_t load_Addr = so_addr.GetLoadAddress(m_exe_ctx->GetTargetPtr());
      if (load_Addr == LLDB_INVALID_ADDRESS) {
        if (error_ptr)
          error_ptr->SetErrorString("failed to resolve load address");
        return false;
      }
      stack.back().GetScalar() = load_Addr;
      stack.back().SetValueType(Value::eValueTypeLoadAddress);
      // Fall through to load address code below...
    }
      LLVM_FALLTHROUGH;
    case Value::eValueTypeLoadAddress:
      if (m_exe_ctx) {
        if (process) {
          lldb::addr_t pointer_addr =
              stack.back().GetScalar().ULongLong(LLDB_INVALID_ADDRESS);
          Status error;
          lldb::addr_t pointer_value =
              process->ReadPointerFromMemory(pointer_addr, error);
          if (pointer_value != LLDB_INVALID_ADDRESS) {
            stack.back().GetScalar() = pointer_value;
            stack.back().ClearContext();
          } else {
            if (error_ptr)
              error_ptr->SetErrorStringWithFormat(
                  "Failed to dereference pointer from 0x%" PRIx64
                  " for DW_OP_deref: %s\n",
                  pointer_addr, error.AsCString());
            return false;
          }
        } else {
          if (error_ptr)
            error_ptr->SetErrorString("NULL process for DW_OP_deref.\n");
          return false;
        }
      } else {
        if (error_ptr)
          error_ptr->SetErrorString(
              "NULL execution context for DW_OP_deref.\n");
        return false;
      }
      break;

    default:
      break;
    }

  } break;

  // OPCODE: DW_OP_deref_size
  // OPERANDS: 1
  //  1 - uint8_t that specifies the size of the data to dereference.
  // DESCRIPTION: Behaves like the DW_OP_deref operation: it pops the top
  // stack entry and treats it as an address. The value retrieved from that
  // address is pushed. In the DW_OP_deref_size operation, however, the size
  // in bytes of the data retrieved from the dereferenced address is
  // specified by the single operand. This operand is a 1-byte unsigned
  // integral constant whose value may not be larger than the size of an
  // address on the target machine. The data retrieved is zero extended to
  // the size of an address on the target machine before being pushed on the
  // expression stack.
  case DW_OP_deref_size: {
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack empty for DW_OP_deref_size.");
      return false;
    }
    uint8_t size = opcodes.GetU8(&offset);
    Value::ValueType value_type = stack.back().GetValueType();
    switch (value_type) {
    case Value::eValueTypeHostAddress: {
      void *src = (void *)stack.back().GetScalar().ULongLong();
      intptr_t ptr;
      ::memcpy(&ptr, src, sizeof(void *));
      // I can't decide whether the size operand should apply to the bytes in
      // their
      // lldb-host endianness or the target endianness.. I doubt this'll ever
      // come up but I'll opt for assuming big endian regardless.
      switch (size) {
      case 1:
        ptr = ptr & 0xff;
        break;
      case 2:
        ptr = ptr & 0xffff;
        break;
      case 3:
        ptr = ptr & 0xffffff;
        break;
      case 4:
        ptr = ptr & 0xffffffff;
        break;
      // the casts are added to work around the case where intptr_t is a 32
      // bit quantity;
      // presumably we won't hit the 5..7 cases if (void*) is 32-bits in this
      // program.
      case 5:
        ptr = (intptr_t)ptr & 0xffffffffffULL;
        break;
      case 6:
        ptr = (intptr_t)ptr & 0xffffffffffffULL;
        break;
      case 7:
        ptr = (intptr_t)ptr & 0xffffffffffffffULL;
        break;
      default:
        break;
      }
      stack.back().GetScalar() = ptr;
      stack.back().ClearContext();
    } break;
    case Value::eValueTypeLoadAddress:
      if (m_exe_ctx) {
        if (process) {
          lldb::addr_t pointer_addr =
              stack.back().GetScalar().ULongLong(LLDB_INVALID_ADDRESS);
          uint8_t addr_bytes[sizeof(lldb::addr_t)];
          Status error;
          if (process->ReadMemory(pointer_addr, &addr_bytes, size, error) ==
              size) {
            DataExtractor addr_data(addr_bytes, sizeof(addr_bytes),
                                    process->GetByteOrder(), size);
            lldb::offset_t addr_data_offset = 0;
            switch (size) {
            case 1:
              stack.back().GetScalar() = addr_data.GetU8(&addr_data_offset);
              break;
            case 2:
              stack.back().GetScalar() = addr_data.GetU16(&addr_data_offset);
              break;
            case 4:
              stack.back().GetScalar() = addr_data.GetU32(&addr_data_offset);
              break;
            case 8:
              stack.back().GetScalar() = addr_data.GetU64(&addr_data_offset);
              break;
            default:
              stack.back().GetScalar() =
                  addr_data.GetAddress(&addr_data_offset);
            }
            stack.back().ClearContext();
          } else {
            if (error_ptr)
              error_ptr->SetErrorStringWithFormat(
                  "Failed to dereference pointer from 0x%" PRIx64
                  " for DW_OP_deref: %s\n",
                  pointer_addr, error.AsCString());
            return false;
          }
        } else {
          if (error_ptr)
            error_ptr->SetErrorStringWithFormat(
                "NULL process for DW_OP_deref.\n");
          return false;
        }
      } else {
        if (error_ptr)
          error_ptr->SetErrorStringWithFormat(
              "NULL execution context for DW_OP_deref.\n");
        return false;
      }
      break;

    default:
      break;
    }

  } break;

  // OPCODE: DW_OP_xderef_size
  // OPERANDS: 1
  //  1 - uint8_t that specifies the size of the data to dereference.
  // DESCRIPTION: Behaves like the DW_OP_xderef operation: the entry at
  // the top of the stack is treated as an address. The second stack entry is
  // treated as an "address space identifier" for those architectures that
  // support multiple address spaces. The top two stack elements are popped,
  // a data item is retrieved through an implementation-defined address
  // calculation and pushed as the new stack top. In the DW_OP_xderef_size
  // operation, however, the size in bytes of the data retrieved from the
  // dereferenced address is specified by the single operand. This operand is
  // a 1-byte unsigned integral constant whose value may not be larger than
  // the size of an address on the target machine. The data retrieved is zero
  // extended to the size of an address on the target machine before being
  // pushed on the expression stack.
  case DW_OP_xderef_size:
    if (error_ptr)
      error_ptr->SetErrorString("Unimplemented opcode: DW_OP_xderef_size.");
    return false;
  // OPCODE: DW_OP_xderef
  // OPERANDS: none
  // DESCRIPTION: Provides an extended dereference mechanism. The entry at
  // the top of the stack is treated as an address. The second stack entry is
  // treated as an "address space identifier" for those architectures that
  // support multiple address spaces. The top two stack elements are popped,
  // a data item is retrieved through an implementation-defined address
  // calculation and pushed as the new stack top. The size of the data
  // retrieved from the dereferenced address is the size of an address on the
  // target machine.
  case DW_OP_xderef:
    if (error_ptr)
      error_ptr->SetErrorString("Unimplemented opcode: DW_OP_xderef.");
    return false;

  // All DW_OP_constXXX opcodes have a single operand as noted below:
  //
  // Opcode           Operand 1
  // DW_OP_const1u    1-byte unsigned integer constant DW_OP_const1s
  // 1-byte signed integer constant DW_OP_const2u    2-byte unsigned integer
  // constant DW_OP_const2s    2-byte signed integer constant DW_OP_const4u
  // 4-byte unsigned integer constant DW_OP_const4s    4-byte signed integer
  // constant DW_OP_const8u    8-byte unsigned integer constant DW_OP_const8s
  // 8-byte signed integer constant DW_OP_constu     unsigned LEB128 integer
  // constant DW_OP_consts     signed LEB128 integer constant
  case DW_OP_const1u:
    stack.push_back(Scalar((uint8_t)opcodes.GetU8(&offset)));
    break;
  case DW_OP_const1s:
    stack.push_back(Scalar((int8_t)opcodes.GetU8(&offset)));
    break;
  case DW_OP_const2u:
    stack.push_back(Scalar((uint16_t)opcodes.GetU16(&offset)));
    break;
  case DW_OP_const2s:
    stack.push_back(Scalar((int16_t)opcodes.GetU16(&offset)));
    break;
  case DW_OP_const4u:
    stack.push_back(Scalar((uint32_t)opcodes.GetU32(&offset)));
    break;
  case DW_OP_const4s:
    stack.push_back(Scalar((int32_t)opcodes.GetU32(&offset)));
    break;
  case DW_OP_const8u:
    stack.push_back(Scalar((uint64_t)opcodes.GetU64(&offset)));
    break;
  case DW_OP_const8s:
    stack.push_back(Scalar((int64_t)opcodes.GetU64(&offset)));
    break;
  case DW_OP_constu:
    stack.push_back(Scalar(opcodes.GetULEB128(&offset)));
    break;
  case DW_OP_consts:
    stack.push_back(Scalar(opcodes.GetSLEB128(&offset)));
    break;

  // OPCODE: DW_OP_dup
  // OPERANDS: none
  // DESCRIPTION: duplicates the value at the top of the stack
  case DW_OP_dup:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString("Expression stack empty for DW_OP_dup.");
      return false;
    } else
      stack.push_back(stack.back());
    break;

  // OPCODE: DW_OP_drop
  // OPERANDS: none
  // DESCRIPTION: pops the value at the top of the stack
  case DW_OP_drop:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString("Expression stack empty for DW_OP_drop.");
      return false;
    } else
      stack.pop_back();
    break;

  // OPCODE: DW_OP_over
  // OPERANDS: none
  // DESCRIPTION: Duplicates the entry currently second in the stack at
  // the top of the stack.
  case DW_OP_over:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_over.");
      return false;
    } else
      stack.push_back(stack[stack.size() - 2]);
    break;

  // OPCODE: DW_OP_pick
  // OPERANDS: uint8_t index into the current stack
  // DESCRIPTION: The stack entry with the specified index (0 through 255,
  // inclusive) is pushed on the stack
  case DW_OP_pick: {
    uint8_t pick_idx = opcodes.GetU8(&offset);
    if (pick_idx < stack.size())
      stack.push_back(stack[stack.size() - 1 - pick_idx]);
    else {
      if (error_ptr)
        error_ptr->SetErrorStringWithFormat(
            "Index %u out of range for DW_OP_pick.\n", pick_idx);
      return false;
    }
  } break;

  // OPCODE: DW_OP_swap
  // OPERANDS: none
  // DESCRIPTION: swaps the top two stack entries. The entry at the top
  // of the stack becomes the second stack entry, and the second entry
  // becomes the top of the stack
  case DW_OP_swap:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_swap.");
      return false;
    } else {
      tmp = stack.back();
      stack.back() = stack[stack.size() - 2];
      stack[stack.size() - 2] = tmp;
    }
    break;

  // OPCODE: DW_OP_rot
  // OPERANDS: none
  // DESCRIPTION: Rotates the first three stack entries. The entry at
  // the top of the stack becomes the third stack entry, the second entry
  // becomes the top of the stack, and the third entry becomes the second
  // entry.
  case DW_OP_rot:
    if (stack.size() < 3) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 3 items for DW_OP_rot.");
      return false;
    } else {
      size_t last_idx = stack.size() - 1;
      Value old_top = stack[last_idx];
      stack[last_idx] = stack[last_idx - 1];
      stack[last_idx - 1] = stack[last_idx - 2];
      stack[last_idx - 2] = old_top;
    }
    break;

  // OPCODE: DW_OP_abs
  // OPERANDS: none
  // DESCRIPTION: pops the top stack entry, interprets it as a signed
  // value and pushes its absolute value. If the absolute value can not be
  // represented, the result is undefined.
  case DW_OP_abs:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_abs.");
      return false;
    } else if (!stack.back().ResolveValue(m_exe_ctx).AbsoluteValue()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Failed to take the absolute value of the first stack item.");
      return false;
    }
    break;

  // OPCODE: DW_OP_and
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, performs a bitwise and
  // operation on the two, and pushes the result.
  case DW_OP_and:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_and.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) & tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_div
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, divides the former second
  // entry by the former top of the stack using signed division, and pushes
  // the result.
  case DW_OP_div:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_div.");
      return false;
    } else {
      tmp = stack.back();
      if (tmp.ResolveValue(m_exe_ctx).IsZero()) {
        if (error_ptr)
          error_ptr->SetErrorString("Divide by zero.");
        return false;
      } else {
        stack.pop_back();
        stack.back() =
            stack.back().ResolveValue(m_exe_ctx) / tmp.ResolveValue(m_exe_ctx);
        if (!stack.back().ResolveValue(m_exe_ctx).IsValid()) {
          if (error_ptr)
            error_ptr->SetErrorString("Divide failed.");
          return false;
        }
      }
    }
    break;

  // OPCODE: DW_OP_minus
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, subtracts the former top
  // of the stack from the former second entry, and pushes the result.
  case DW_OP_minus:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_minus.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) - tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_mod
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values and pushes the result of
  // the calculation: former second stack entry modulo the former top of the
  // stack.
  case DW_OP_mod:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_mod.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) % tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_mul
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, multiplies them
  // together, and pushes the result.
  case DW_OP_mul:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_mul.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) * tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_neg
  // OPERANDS: none
  // DESCRIPTION: pops the top stack entry, and pushes its negation.
  case DW_OP_neg:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_neg.");
      return false;
    } else {
      if (!stack.back().ResolveValue(m_exe_ctx).UnaryNegate()) {
        if (error_ptr)
          error_ptr->SetErrorString("Unary negate failed.");
        return false;
      }
    }
    break;

  // OPCODE: DW_OP_not
  // OPERANDS: none
  // DESCRIPTION: pops the top stack entry, and pushes its bitwise
  // complement
  case DW_OP_not:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_not.");
      return false;
    } else {
      if (!stack.back().ResolveValue(m_exe_ctx).OnesComplement()) {
        if (error_ptr)
          error_ptr->SetErrorString("Logical NOT failed.");
        return false;
      }
    }
    break;

  // OPCODE: DW_OP_or
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, performs a bitwise or
  // operation on the two, and pushes the result.
  case DW_OP_or:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_or.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) | tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_plus
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, adds them together, and
  // pushes the result.
  case DW_OP_plus:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_plus.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().GetScalar() += tmp.GetScalar();
    }
    break;

  // OPCODE: DW_OP_plus_uconst
  // OPERANDS: none
  // DESCRIPTION: pops the top stack entry, adds it to the unsigned LEB128
  // constant operand and pushes the result.
  case DW_OP_plus_uconst:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_plus_uconst.");
      return false;
    } else {
      const uint64_t uconst_value = opcodes.GetULEB128(&offset);
      // Implicit conversion from a UINT to a Scalar...
      stack.back().GetScalar() += uconst_value;
      if (!stack.back().GetScalar().IsValid()) {
        if (error_ptr)
          error_ptr->SetErrorString("DW_OP_plus_uconst failed.");
        return false;
      }
    }
    break;

  // OPCODE: DW_OP_shl
  // OPERANDS: none
  // DESCRIPTION:  pops the top two stack entries, shifts the former
  // second entry left by the number of bits specified by the former top of
  // the stack, and pushes the result.
  case DW_OP_shl:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_shl.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) <<= tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_shr
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, shifts the former second
  // entry right logically (filling with zero bits) by the number of bits
  // specified by the former top of the stack, and pushes the result.
  case DW_OP_shr:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_shr.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      if (!stack.back().ResolveValue(m_exe_ctx).ShiftRightLogical(
              tmp.ResolveValue(m_exe_ctx))) {
        if (error_ptr)
          error_ptr->SetErrorString("DW_OP_shr failed.");
        return false;
      }
    }
    break;

  // OPCODE: DW_OP_shra
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, shifts the former second
  // entry right arithmetically (divide the magnitude by 2, keep the same
  // sign for the result) by the number of bits specified by the former top
  // of the stack, and pushes the result.
  case DW_OP_shra:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_shra.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) >>= tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_xor
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack entries, performs the bitwise
  // exclusive-or operation on the two, and pushes the result.
  case DW_OP_xor:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_xor.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) ^ tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_skip
  // OPERANDS: int16_t
  // DESCRIPTION:  An unconditional branch. Its single operand is a 2-byte
  // signed integer constant. The 2-byte constant is the number of bytes of
  // the DWARF expression to skip forward or backward from the current
  // operation, beginning after the 2-byte constant.
  case DW_OP_skip: {
    int16_t skip_offset = (int16_t)opcodes.GetU16(&offset);
    lldb::offset_t new_offset = offset + skip_offset;
    if (opcodes.ValidOffset(new_offset))
      offset = new_offset;
    else {
      if (error_ptr)
        error_ptr->SetErrorString("Invalid opcode offset in DW_OP_skip.");
      return false;
    }
  } break;

  // OPCODE: DW_OP_bra
  // OPERANDS: int16_t
  // DESCRIPTION: A conditional branch. Its single operand is a 2-byte
  // signed integer constant. This operation pops the top of stack. If the
  // value popped is not the constant 0, the 2-byte constant operand is the
  // number of bytes of the DWARF expression to skip forward or backward from
  // the current operation, beginning after the 2-byte constant.
  case DW_OP_bra:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_bra.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      int16_t bra_offset = (int16_t)opcodes.GetU16(&offset);
      Scalar zero(0);
      if (tmp.ResolveValue(m_exe_ctx) != zero) {
        lldb::offset_t new_offset = offset + bra_offset;
        if (opcodes.ValidOffset(new_offset))
          offset = new_offset;
        else {
          if (error_ptr)
            error_ptr->SetErrorString("Invalid opcode offset in DW_OP_bra.");
          return false;
        }
      }
    }
    break;

  // OPCODE: DW_OP_eq
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // equals (==) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_eq:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_eq.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) == tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_ge
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // greater than or equal to (>=) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_ge:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_ge.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) >= tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_gt
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // greater than (>) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_gt:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_gt.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) > tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_le
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // less than or equal to (<=) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_le:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_le.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) <= tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_lt
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // less than (<) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_lt:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_lt.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) < tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_ne
  // OPERANDS: none
  // DESCRIPTION: pops the top two stack values, compares using the
  // not equal (!=) operator.
  // STACK RESULT: push the constant value 1 onto the stack if the result
  // of the operation is true or the constant value 0 if the result of the
  // operation is false.
  case DW_OP_ne:
    if (stack.size() < 2) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 2 items for DW_OP_ne.");
      return false;
    } else {
      tmp = stack.back();
      stack.pop_back();
      stack.back().ResolveValue(m_exe_ctx) =
          stack.back().ResolveValue(m_exe_ctx) != tmp.ResolveValue(m_exe_ctx);
    }
    break;

  // OPCODE: DW_OP_litn
  // OPERANDS: none
  // DESCRIPTION: encode the unsigned literal values from 0 through 31.
  // STACK RESULT: push the unsigned literal constant value onto the top
  // of the stack.
  case DW_OP_lit0:
  case DW_OP_lit1:
  case DW_OP_lit2:
  case DW_OP_lit3:
  case DW_OP_lit4:
  case DW_OP_lit5:
  case DW_OP_lit6:
  case DW_OP_lit7:
  case DW_OP_lit8:
  case DW_OP_lit9:
  case DW_OP_lit10:
  case DW_OP_lit11:
  case DW_OP_lit12:
  case DW_OP_lit13:
  case DW_OP_lit14:
  case DW_OP_lit15:
  case DW_OP_lit16:
  case DW_OP_lit17:
  case DW_OP_lit18:
  case DW_OP_lit19:
  case DW_OP_lit20:
  case DW_OP_lit21:
  case DW_OP_lit22:
  case DW_OP_lit23:
  case DW_OP_lit24:
  case DW_OP_lit25:
  case DW_OP_lit26:
  case DW_OP_lit27:
  case DW_OP_lit28:
  case DW_OP_lit29:
  case DW_OP_lit30:
  case DW_OP_lit31:
    stack.push_back(Scalar((uint64_t)(op - DW_OP_lit0)));
    break;

  // OPCODE: DW_OP_regN
  // OPERANDS: none
  // DESCRIPTION: Push the value in register n on the top of the stack.
  case DW_OP_reg0:
  case DW_OP_reg1:
  case DW_OP_reg2:
  case DW_OP_reg3:
  case DW_OP_reg4:
  case DW_OP_reg5:
  case DW_OP_reg6:
  case DW_OP_reg7:
  case DW_OP_reg8:
  case DW_OP_reg9:
  case DW_OP_reg10:
  case DW_OP_reg11:
  case DW_OP_reg12:
  case DW_OP_reg13:
  case DW_OP_reg14:
  case DW_OP_reg15:
  case DW_OP_reg16:
  case DW_OP_reg17:
  case DW_OP_reg18:
  case DW_OP_reg19:
  case DW_OP_reg20:
  case DW_OP_reg21:
  case DW_OP_reg22:
  case DW_OP_reg23:
  case DW_OP_reg24:
  case DW_OP_reg25:
  case DW_OP_reg26:
  case DW_OP_reg27:
  case DW_OP_reg28:
  case DW_OP_reg29:
  case DW_OP_reg30:
  case DW_OP_reg31: {
    reg_num = op - DW_OP_reg0;

    if (ReadRegisterValueAsScalar(m_reg_ctx, reg_kind, reg_num, error_ptr, tmp))
      stack.push_back(tmp);
    else
      return false;
  } break;
  // OPCODE: DW_OP_regx
  // OPERANDS:
  //      ULEB128 literal operand that encodes the register.
  // DESCRIPTION: Push the value in register on the top of the stack.
  case DW_OP_regx: {
    reg_num = opcodes.GetULEB128(&offset);
    if (ReadRegisterValueAsScalar(m_reg_ctx, reg_kind, reg_num, error_ptr, tmp))
      stack.push_back(tmp);
    else
      return false;
  } break;

  // OPCODE: DW_OP_bregN
  // OPERANDS:
  //      SLEB128 offset from register N
  // DESCRIPTION: Value is in memory at the address specified by register
  // N plus an offset.
  case DW_OP_breg0:
  case DW_OP_breg1:
  case DW_OP_breg2:
  case DW_OP_breg3:
  case DW_OP_breg4:
  case DW_OP_breg5:
  case DW_OP_breg6:
  case DW_OP_breg7:
  case DW_OP_breg8:
  case DW_OP_breg9:
  case DW_OP_breg10:
  case DW_OP_breg11:
  case DW_OP_breg12:
  case DW_OP_breg13:
  case DW_OP_breg14:
  case DW_OP_breg15:
  case DW_OP_breg16:
  case DW_OP_breg17:
  case DW_OP_breg18:
  case DW_OP_breg19:
  case DW_OP_breg20:
  case DW_OP_breg21:
  case DW_OP_breg22:
  case DW_OP_breg23:
  case DW_OP_breg24:
  case DW_OP_breg25:
  case DW_OP_breg26:
  case DW_OP_breg27:
  case DW_OP_breg28:
  case DW_OP_breg29:
  case DW_OP_breg30:
  case DW_OP_breg31: {
    reg_num = op - DW_OP_breg0;

    if (ReadRegisterValueAsScalar(m_reg_ctx, reg_kind, reg_num, error_ptr,
                                  tmp)) {
      int64_t breg_offset = opcodes.GetSLEB128(&offset);
      tmp.ResolveValue(m_exe_ctx) += (uint64_t)breg_offset;
      tmp.ClearContext();
      stack.push_back(tmp);
      stack.back().SetValueType(Value::eValueTypeLoadAddress);
    } else
      return false;
  } break;
  // OPCODE: DW_OP_bregx
  // OPERANDS: 2
  //      ULEB128 literal operand that encodes the register.
  //      SLEB128 offset from register N
  // DESCRIPTION: Value is in memory at the address specified by register
  // N plus an offset.
  case DW_OP_bregx: {
    reg_num = opcodes.GetULEB128(&offset);

    if (ReadRegisterValueAsScalar(m_reg_ctx, reg_kind, reg_num, error_ptr,
                                  tmp)) {
      int64_t breg_offset = opcodes.GetSLEB128(&offset);
      tmp.ResolveValue(m_exe_ctx) += (uint64_t)breg_offset;
      tmp.ClearContext();
      stack.push_back(tmp);
      stack.back().SetValueType(Value::eValueTypeLoadAddress);
    } else
      return false;
  } break;

  case DW_OP_fbreg:
    if (m_exe_ctx) {
      if (frame) {
        Scalar value;
        if (frame->GetFrameBaseValue(value, error_ptr)) {
          int64_t fbreg_offset = opcodes.GetSLEB128(&offset);
          value += fbreg_offset;
          stack.push_back(value);
          stack.back().SetValueType(Value::eValueTypeLoadAddress);
        } else
          return false;
      } else {
        if (error_ptr)
          error_ptr->SetErrorString(
              "Invalid stack frame in context for DW_OP_fbreg opcode.");
        return false;
      }
    } else {
      if (error_ptr)
        error_ptr->SetErrorString("NULL execution context for DW_OP_fbreg.\n");
      return false;
    }

    break;

  // OPCODE: DW_OP_nop
  // OPERANDS: none
  // DESCRIPTION: A place holder. It has no effect on the location stack
  // or any of its values.
  case DW_OP_nop:
    break;

  // OPCODE: DW_OP_piece
  // OPERANDS: 1
  //      ULEB128: byte size of the piece
  // DESCRIPTION: The operand describes the size in bytes of the piece of
  // the object referenced by the DWARF expression whose result is at the top
  // of the stack. If the piece is located in a register, but does not occupy
  // the entire register, the placement of the piece within that register is
  // defined by the ABI.
  //
  // Many compilers store a single variable in sets of registers, or store a
  // variable partially in memory and partially in registers. DW_OP_piece
  // provides a way of describing how large a part of a variable a particular
  // DWARF expression refers to.
  case DW_OP_piece: {
    const uint64_t piece_byte_size = opcodes.GetULEB128(&offset);

    if (piece_byte_size > 0) {
      Value curr_piece;

      if (stack.empty()) {
        // In a multi-piece expression, this means that the current piece is
        // not available. Fill with zeros for now by resizing the data and
        // appending it
        curr_piece.ResizeData(piece_byte_size);
        // Note that "0" is not a correct value for the unknown bits.
        // It would be better to also return a mask of valid bits together
        // with the expression result, so the debugger can print missing
        // members as "<optimized out>" or something.
        ::memset(curr_piece.GetBuffer().GetBytes(), 0, piece_byte_size);
        pieces.AppendDataToHostBuffer(curr_piece);
      } else {
        Status error;
        // Extract the current piece into "curr_piece"
        Value curr_piece_source_value(stack.back());
        stack.pop_back();

        const Value::ValueType curr_piece_source_value_type =
            curr_piece_source_value.GetValueType();
        switch (curr_piece_source_value_type) {
        case Value::eValueTypeLoadAddress:
          if (process) {
            if (curr_piece.ResizeData(piece_byte_size) == piece_byte_size) {
              lldb::addr_t load_addr =
                  curr_piece_source_value.GetScalar().ULongLong(
                      LLDB_INVALID_ADDRESS);
              if (process->ReadMemory(
                      load_addr, curr_piece.GetBuffer().GetBytes(),
                      piece_byte_size, error) != piece_byte_size) {
                if (error_ptr)
                  error_ptr->SetErrorStringWithFormat(
                      "failed to read memory DW_OP_piece(%" PRIu64
                      ") from 0x%" PRIx64,
                      piece_byte_size, load_addr);
                return false;
              }
            } else {
              if (error_ptr)
                error_ptr->SetErrorStringWithFormat(
                    "failed to resize the piece memory buffer for "
                    "DW_OP_piece(%" PRIu64 ")",
                    piece_byte_size);
              return false;
            }
          }
          break;

        case Value::eValueTypeFileAddress:
        case Value::eValueTypeHostAddress:
          if (error_ptr) {
            lldb::addr_t addr = curr_piece_source_value.GetScalar().ULongLong(
                LLDB_INVALID_ADDRESS);
            error_ptr->SetErrorStringWithFormat(
                "failed to read memory DW_OP_piece(%" PRIu64
                ") from %s address 0x%" PRIx64,
                piece_byte_size,
                curr_piece_source_value.GetValueType() ==
                        Value::eValueTypeFileAddress
                    ? "file"
                    : "host",
                addr);
          }
          return false;

        case Value::eValueTypeScalar: {
          uint32_t bit_size = piece_byte_size * 8;
          uint32_t bit_offset = 0;
          Scalar &scalar = curr_piece_source_value.GetScalar();
          if (!scalar.ExtractBitfield(bit_size, bit_offset)) {
            if (error_ptr)
              error_ptr->SetErrorStringWithFormat(
                  "unable to extract %" PRIu64 " bytes from a %" PRIu64
                  " byte scalar value.",
                  piece_byte_size,
                  (uint64_t)curr_piece_source_value.GetScalar().GetByteSize());
            return false;
          }
          // Create curr_piece with bit_size. By default Scalar
          // grows to the nearest host integer type.
          llvm::APInt fail_value(1, 0, false);
          llvm::APInt ap_int = scalar.UInt128(fail_value);
          assert(ap_int.getBitWidth() >= bit_size);
          llvm::ArrayRef<uint64_t> buf{ap_int.getRawData(),
                                       ap_int.getNumWords()};
          curr_piece.GetScalar() = Scalar(llvm::APInt(bit_size, buf));
        } break;

        case Value::eValueTypeVector: {
          if (curr_piece_source_value.GetVector().length >= piece_byte_size)
            curr_piece_source_value.GetVector().length = piece_byte_size;
          else {
            if (error_ptr)
              error_ptr->SetErrorStringWithFormat(
                  "unable to extract %" PRIu64 " bytes from a %" PRIu64
                  " byte vector value.",
                  piece_byte_size,
                  (uint64_t)curr_piece_source_value.GetVector().length);
            return false;
          }
        } break;
        }

        // Check if this is the first piece?
        if (op_piece_offset == 0) {
          // This is the first piece, we should push it back onto the stack
          // so subsequent pieces will be able to access this piece and add
          // to it.
          if (pieces.AppendDataToHostBuffer(curr_piece) == 0) {
            if (error_ptr)
              error_ptr->SetErrorString("failed to append piece data");
            return false;
          }
        } else {
          // If this is the second or later piece there should be a value on
          // the stack.
          if (pieces.GetBuffer().GetByteSize() != op_piece_offset) {
            if (error_ptr)
              error_ptr->SetErrorStringWithFormat(
                  "DW_OP_piece for offset %" PRIu64
                  " but top of stack is of size %" PRIu64,
                  op_piece_offset, pieces.GetBuffer().GetByteSize());
            return false;
          }

          if (pieces.AppendDataToHostBuffer(curr_piece) == 0) {
            if (error_ptr)
              error_ptr->SetErrorString("failed to append piece data");
            return false;
          }
        }
      }
      op_piece_offset += piece_byte_size;
    }
  } break;

  case DW_OP_bit_piece: // 0x9d ULEB128 bit size, ULEB128 bit offset (DWARF3);
    if (stack.size() < 1) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_bit_piece.");
      return false;
    } else {
      const uint64_t piece_bit_size = opcodes.GetULEB128(&offset);
      const uint64_t piece_bit_offset = opcodes.GetULEB128(&offset);
      switch (stack.back().GetValueType()) {
      case Value::eValueTypeScalar: {
        if (!stack.back().GetScalar().ExtractBitfield(piece_bit_size,
                                                      piece_bit_offset)) {
          if (error_ptr)
            error_ptr->SetErrorStringWithFormat(
                "unable to extract %" PRIu64 " bit value with %" PRIu64
                " bit offset from a %" PRIu64 " bit scalar value.",
                piece_bit_size, piece_bit_offset,
                (uint64_t)(stack.back().GetScalar().GetByteSize() * 8));
          return false;
        }
      } break;

      case Value::eValueTypeFileAddress:
      case Value::eValueTypeLoadAddress:
      case Value::eValueTypeHostAddress:
        if (error_ptr) {
          error_ptr->SetErrorStringWithFormat(
              "unable to extract DW_OP_bit_piece(bit_size = %" PRIu64
              ", bit_offset = %" PRIu64 ") from an address value.",
              piece_bit_size, piece_bit_offset);
        }
        return false;

      case Value::eValueTypeVector:
        if (error_ptr) {
          error_ptr->SetErrorStringWithFormat(
              "unable to extract DW_OP_bit_piece(bit_size = %" PRIu64
              ", bit_offset = %" PRIu64 ") from a vector value.",
              piece_bit_size, piece_bit_offset);
        }
        return false;
      }
    }
    break;

  // OPCODE: DW_OP_push_object_address
  // OPERANDS: none
  // DESCRIPTION: Pushes the address of the object currently being
  // evaluated as part of evaluation of a user presented expression. This
  // object may correspond to an independent variable described by its own
  // DIE or it may be a component of an array, structure, or class whose
  // address has been dynamically determined by an earlier step during user
  // expression evaluation.
  case DW_OP_push_object_address:
    if (m_object_address_ptr)
      stack.push_back(*m_object_address_ptr);
    else {
      if (error_ptr)
        error_ptr->SetErrorString("DW_OP_push_object_address used without "
                                  "specifying an object address");
      return false;
    }
    break;

  // OPCODE: DW_OP_call2
  // OPERANDS:
  //      uint16_t compile unit relative offset of a DIE
  // DESCRIPTION: Performs subroutine calls during evaluation
  // of a DWARF expression. The operand is the 2-byte unsigned offset of a
  // debugging information entry in the current compilation unit.
  //
  // Operand interpretation is exactly like that for DW_FORM_ref2.
  //
  // This operation transfers control of DWARF expression evaluation to the
  // DW_AT_location attribute of the referenced DIE. If there is no such
  // attribute, then there is no effect. Execution of the DWARF expression of
  // a DW_AT_location attribute may add to and/or remove from values on the
  // stack. Execution returns to the point following the call when the end of
  // the attribute is reached. Values on the stack at the time of the call
  // may be used as parameters by the called expression and values left on
  // the stack by the called expression may be used as return values by prior
  // agreement between the calling and called expressions.
  case DW_OP_call2:
    if (error_ptr)
      error_ptr->SetErrorString("Unimplemented opcode DW_OP_call2.");
    return false;
  // OPCODE: DW_OP_call4
  // OPERANDS: 1
  //      uint32_t compile unit relative offset of a DIE
  // DESCRIPTION: Performs a subroutine call during evaluation of a DWARF
  // expression. For DW_OP_call4, the operand is a 4-byte unsigned offset of
  // a debugging information entry in  the current compilation unit.
  //
  // Operand interpretation DW_OP_call4 is exactly like that for
  // DW_FORM_ref4.
  //
  // This operation transfers control of DWARF expression evaluation to the
  // DW_AT_location attribute of the referenced DIE. If there is no such
  // attribute, then there is no effect. Execution of the DWARF expression of
  // a DW_AT_location attribute may add to and/or remove from values on the
  // stack. Execution returns to the point following the call when the end of
  // the attribute is reached. Values on the stack at the time of the call
  // may be used as parameters by the called expression and values left on
  // the stack by the called expression may be used as return values by prior
  // agreement between the calling and called expressions.
  case DW_OP_call4:
    if (error_ptr)
      error_ptr->SetErrorString("Unimplemented opcode DW_OP_call4.");
    return false;

  // OPCODE: DW_OP_stack_value
  // OPERANDS: None
  // DESCRIPTION: Specifies that the object does not exist in memory but
  // rather is a constant value.  The value from the top of the stack is the
  // value to be used.  This is the actual object value and not the location.
  case DW_OP_stack_value:
    if (stack.empty()) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_stack_value.");
      return false;
    }
    stack.back().SetValueType(Value::eValueTypeScalar);
    break;

  // OPCODE: DW_OP_convert
  // OPERANDS: 1
  //      A ULEB128 that is either a DIE offset of a
  //      DW_TAG_base_type or 0 for the generic (pointer-sized) type.
  //
  // DESCRIPTION: Pop the top stack element, convert it to a
  // different type, and push the result.
  case DW_OP_convert: {
    if (stack.size() < 1) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "Expression stack needs at least 1 item for DW_OP_convert.");
      return false;
    }
    const uint64_t die_offset = opcodes.GetULEB128(&offset);
    uint64_t bit_size;
    bool sign;
    if (die_offset == 0) {
      // The generic type has the size of an address on the target
      // machine and an unspecified signedness. Scalar has no
      // "unspecified signedness", so we use unsigned types.
      if (!module_sp) {
        if (error_ptr)
          error_ptr->SetErrorString("No module");
        return false;
      }
      sign = false;
      bit_size = module_sp->GetArchitecture().GetAddressByteSize() * 8;
      if (!bit_size) {
        if (error_ptr)
          error_ptr->SetErrorString("unspecified architecture");
        return false;
      }
    } else {
      // Retrieve the type DIE that the value is being converted to.
      // FIXME: the constness has annoying ripple effects.
      DWARFDIE die = const_cast<DWARFUnit *>(dwarf_cu)->GetDIE(die_offset);
      if (!die) {
        if (error_ptr)
          error_ptr->SetErrorString("Cannot resolve DW_OP_convert type DIE");
        return false;
      }
      uint64_t encoding =
          die.GetAttributeValueAsUnsigned(DW_AT_encoding, DW_ATE_hi_user);
      bit_size = die.GetAttributeValueAsUnsigned(DW_AT_byte_size, 0) * 8;
      if (!bit_size)
        bit_size = die.GetAttributeValueAsUnsigned(DW_AT_bit_size, 0);
      if (!bit_size) {
        if (error_ptr)
          error_ptr->SetErrorString("Unsupported type size in DW_OP_convert");
        return false;
      }
      switch (encoding) {
      case DW_ATE_signed:
      case DW_ATE_signed_char:
        sign = false;
        break;
      case DW_ATE_unsigned:
      case DW_ATE_unsigned_char:
        sign = false;
        break;
      default:
        if (error_ptr)
          error_ptr->SetErrorString("Unsupported encoding in DW_OP_convert");
        return false;
      }
    }
    Scalar &top = stack.back().ResolveValue(m_exe_ctx);
    top.TruncOrExtendTo(bit_size, sign);
    break;
  }

  // OPCODE: DW_OP_call_frame_cfa
  // OPERANDS: None
  // DESCRIPTION: Specifies a DWARF expression that pushes the value of
  // the canonical frame address consistent with the call frame information
  // located in .debug_frame (or in the FDEs of the eh_frame section).
  case DW_OP_call_frame_cfa:
    if (frame) {
      // Note that we don't have to parse FDEs because this DWARF expression
      // is commonly evaluated with a valid stack frame.
      StackID id = frame->GetStackID();
      addr_t cfa = id.GetCallFrameAddress();
      if (cfa != LLDB_INVALID_ADDRESS) {
        stack.push_back(Scalar(cfa));
        stack.back().SetValueType(Value::eValueTypeLoadAddress);
      } else if (error_ptr)
        error_ptr->SetErrorString("Stack frame does not include a canonical "
                                  "frame address for DW_OP_call_frame_cfa "
                                  "opcode.");
    } else {
      if (error_ptr)
        error_ptr->SetErrorString("Invalid stack frame in context for "
                                  "DW_OP_call_frame_cfa opcode.");
      return false;
    }
    break;

  // OPCODE: DW_OP_form_tls_address (or the old pre-DWARFv3 vendor extension
  // opcode, DW_OP_GNU_push_tls_address)
  // OPERANDS: none
  // DESCRIPTION: Pops a TLS offset from the stack, converts it to
  // an address in the current thread's thread-local storage block, and
  // pushes it on the stack.
  case DW_OP_form_tls_address:
  case DW_OP_GNU_push_tls_address: {
    if (stack.size() < 1) {
      if (error_ptr) {
        if (op == DW_OP_form_tls_address)
          error_ptr->SetErrorString(
              "DW_OP_form_tls_address needs an argument.");
        else
          error_ptr->SetErrorString(
              "DW_OP_GNU_push_tls_address needs an argument.");
      }
      return false;
    }

    if (!m_exe_ctx || !module_sp) {
      if (error_ptr)
        error_ptr->SetErrorString("No context to evaluate TLS within.");
      return false;
    }

    Thread *thread = m_exe_ctx->GetThreadPtr();
    if (!thread) {
      if (error_ptr)
        error_ptr->SetErrorString("No thread to evaluate TLS within.");
      return false;
    }

    // Lookup the TLS block address for this thread and module.
    const addr_t tls_file_addr =
        stack.back().GetScalar().ULongLong(LLDB_INVALID_ADDRESS);
    const addr_t tls_load_addr =
        thread->GetThreadLocalData(module_sp, tls_file_addr);

    if (tls_load_addr == LLDB_INVALID_ADDRESS) {
      if (error_ptr)
        error_ptr->SetErrorString(
            "No TLS data currently exists for this thread.");
      return false;
    }

    stack.back().GetScalar() = tls_load_addr;
    stack.back().SetValueType(Value::eValueTypeLoadAddress);
  } break;

  // OPCODE: DW_OP_addrx (DW_OP_GNU_addr_index is the legacy name.)
  // OPERANDS: 1
  //      ULEB128: index to the .debug_addr section
  // DESCRIPTION: Pushes an address to the stack from the .debug_addr
  // section with the base address specified by the DW_AT_addr_base attribute
  // and the 0 based index is the ULEB128 encoded index.
  case DW_OP_addrx:
  case DW_OP_GNU_addr_index: {
    if (!dwarf_cu) {
      if (error_ptr)
        error_ptr->SetErrorString("DW_OP_GNU_addr_index found without a "
                                  "compile unit being specified");
      return false;
    }
    uint64_t index = opcodes.GetULEB128(&offset);
    lldb::addr_t value =
        DWARFExpression::ReadAddressFromDebugAddrSection(dwarf_cu, index);
    stack.push_back(Scalar(value));
    stack.back().SetValueType(Value::eValueTypeFileAddress);
  } break;

  // OPCODE: DW_OP_GNU_const_index
  // OPERANDS: 1
  //      ULEB128: index to the .debug_addr section
  // DESCRIPTION: Pushes an constant with the size of a machine address to
  // the stack from the .debug_addr section with the base address specified
  // by the DW_AT_addr_base attribute and the 0 based index is the ULEB128
  // encoded index.
  case DW_OP_GNU_const_index: {
    if (!dwarf_cu) {
      if (error_ptr)
        error_ptr->SetErrorString("DW_OP_GNU_const_index found without a "
                                  "compile unit being specified");
      return false;
    }
    uint64_t index = opcodes.GetULEB128(&offset);
    lldb::addr_t value =
        DWARFExpression::ReadAddressFromDebugAddrSection(dwarf_cu, index);
    stack.push_back(Scalar(value));
  } break;

  case DW_OP_GNU_entry_value:
  case DW_OP_entry_value: {
    if (!Evaluate_DW_OP_entry_value(stack, m_exe_ctx, m_reg_ctx, opcodes,
                                    offset, error_ptr, log)) {
      LLDB_ERRORF(error_ptr, "Could not evaluate %s.", DW_OP_value_to_name(op));
      return false;
    }
    break;
  }

  default:
    if (error_ptr)
      error_ptr->SetErrorStringWithFormatv(
          "Unhandled opcode {0} in DWARFExpression", LocationAtom(op));
    return false;
  }

  return true;
}
