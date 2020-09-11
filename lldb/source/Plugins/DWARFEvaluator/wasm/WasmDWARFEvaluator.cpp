//===-- WasmDWARFEvaluator.cpp --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "WasmDWARFEvaluator.h"

#include "Plugins/ObjectFile/wasm/ObjectFileWasm.h"
#include "Plugins/Process/wasm/ProcessWasm.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Value.h"
#include "lldb/Core/dwarf.h"
#include "lldb/Expression/DWARFExpression.h"

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::wasm;

bool WasmDWARFEvaluator::Evaluate(const uint8_t op, Process *process,
                                  StackFrame *frame, std::vector<Value> &stack,
                                  const DataExtractor &opcodes,
                                  lldb::offset_t &offset, Value &pieces,
                                  uint64_t &op_piece_offset, Log *log,
                                  Status *error_ptr) {
  lldb::ModuleSP module_sp = m_dwarf_expression.GetModule();

  switch (op) {
  case DW_OP_WASM_location: {
    if (frame) {
      const llvm::Triple::ArchType machine =
          frame->CalculateTarget()->GetArchitecture().GetMachine();
      if (machine != llvm::Triple::wasm32) {
        if (error_ptr)
          error_ptr->SetErrorString("Invalid target architecture for "
                                    "DW_OP_WASM_location opcode.");
        return false;
      }

      ProcessWasm *wasm_process =
          static_cast<wasm::ProcessWasm *>(frame->CalculateProcess().get());
      int frame_index = frame->GetConcreteFrameIndex();
      uint64_t wasm_op = opcodes.GetULEB128(&offset);
      uint64_t index = opcodes.GetULEB128(&offset);
      uint8_t buf[16];
      size_t size = 0;
      switch (wasm_op) {
      case 0: // Local
        if (!wasm_process->GetWasmLocal(frame_index, index, buf, 16, size)) {
          return false;
        }
        break;
      case 1: // Global
        if (!wasm_process->GetWasmGlobal(frame_index, index, buf, 16, size)) {
          return false;
        }
        break;
      case 2: // Operand Stack
        if (!wasm_process->GetWasmStackValue(frame_index, index, buf, 16,
                                             size)) {
          return false;
        }
        break;
      default:
        return false;
      }

      if (size == sizeof(uint32_t)) {
        uint32_t value;
        memcpy(&value, buf, size);
        stack.push_back(Scalar(value));
      } else if (size == sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, buf, size);
        stack.push_back(Scalar(value));
      } else
        return false;
    } else {
      if (error_ptr)
        error_ptr->SetErrorString("Invalid stack frame in context for "
                                  "DW_OP_WASM_location opcode.");
      return false;
    }
  } break;

  case DW_OP_addr: {
    /// {addr} is an offset in the module Data section.
    lldb::addr_t addr = opcodes.GetAddress(&offset);
    uint32_t wasm_module_id =
        module_sp->GetObjectFile()->GetBaseAddress().GetOffset() >> 32;
    wasm_addr_t wasm_addr(WasmAddressType::Data, wasm_module_id, addr);
    stack.push_back(Scalar(wasm_addr));
    stack.back().SetValueType(Value::eValueTypeLoadAddress);
  } break;

  case DW_OP_fbreg:
    if (m_exe_ctx) {
      if (frame) {
        Scalar value;
        if (frame->GetFrameBaseValue(value, error_ptr)) {
          // The value is an address in the Wasm Memory space.
          int64_t fbreg_offset = opcodes.GetSLEB128(&offset);
          uint32_t wasm_module_id =
              module_sp->GetObjectFile()->GetBaseAddress().GetOffset() >> 32;
          wasm_addr_t wasm_addr(WasmAddressType::Memory, wasm_module_id,
                                value.ULong() + fbreg_offset);
          stack.push_back(Scalar(wasm_addr));
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
        error_ptr->SetErrorStringWithFormat(
            "NULL execution context for DW_OP_fbreg.\n");
      return false;
    }
    break;

  default:
    return DWARFEvaluator::Evaluate(op, process, frame, stack, opcodes, offset,
                                    pieces, op_piece_offset, log, error_ptr);
  }
  return true;
}
