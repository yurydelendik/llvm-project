//===-- DWARFExpression.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Expression/DWARFExpression.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/Value.h"
#include "lldb/Core/dwarf.h"
#include "lldb/Expression/DWARFEvaluator.h"
#include "lldb/Expression/DWARFEvaluatorFactory.h"
#include "lldb/Utility/DataEncoder.h"
#include "lldb/Utility/Log.h"

#include "lldb/Symbol/Function.h"

#include "lldb/Target/ABI.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"

#include "Plugins/SymbolFile/DWARF/DWARFUnit.h"

using namespace lldb;
using namespace lldb_private;

lldb::addr_t
DWARFExpression::ReadAddressFromDebugAddrSection(const DWARFUnit *dwarf_cu,
                                                 uint32_t index) {
  uint32_t index_size = dwarf_cu->GetAddressByteSize();
  dw_offset_t addr_base = dwarf_cu->GetAddrBase();
  lldb::offset_t offset = addr_base + index * index_size;
  const DWARFDataExtractor &data =
      dwarf_cu->GetSymbolFileDWARF().GetDWARFContext().getOrLoadAddrData();
  if (data.ValidOffsetForDataOfSize(offset, index_size))
    return data.GetMaxU64_unchecked(&offset, index_size);
  return LLDB_INVALID_ADDRESS;
}

// DWARFExpression constructor
DWARFExpression::DWARFExpression()
    : m_module_wp(), m_data(), m_dwarf_cu(nullptr),
      m_reg_kind(eRegisterKindDWARF) {}

DWARFExpression::DWARFExpression(lldb::ModuleSP module_sp,
                                 const DataExtractor &data,
                                 const DWARFUnit *dwarf_cu)
    : m_module_wp(), m_data(data), m_dwarf_cu(dwarf_cu),
      m_reg_kind(eRegisterKindDWARF) {
  if (module_sp)
    m_module_wp = module_sp;
}

// Destructor
DWARFExpression::~DWARFExpression() {}

bool DWARFExpression::IsValid() const { return m_data.GetByteSize() > 0; }

void DWARFExpression::UpdateValue(uint64_t const_value,
                                  lldb::offset_t const_value_byte_size,
                                  uint8_t addr_byte_size) {
  if (!const_value_byte_size)
    return;

  m_data.SetData(
      DataBufferSP(new DataBufferHeap(&const_value, const_value_byte_size)));
  m_data.SetByteOrder(endian::InlHostByteOrder());
  m_data.SetAddressByteSize(addr_byte_size);
}

void DWARFExpression::DumpLocation(Stream *s, const DataExtractor &data,
                                   lldb::DescriptionLevel level,
                                   ABI *abi) const {
  llvm::DWARFExpression(data.GetAsLLVM(), data.GetAddressByteSize())
      .print(s->AsRawOstream(), abi ? &abi->GetMCRegisterInfo() : nullptr,
             nullptr);
}

void DWARFExpression::SetLocationListAddresses(addr_t cu_file_addr,
                                               addr_t func_file_addr) {
  m_loclist_addresses = LoclistAddresses{cu_file_addr, func_file_addr};
}

RegisterKind DWARFExpression::GetRegisterKind() const { return m_reg_kind; }

void DWARFExpression::SetRegisterKind(RegisterKind reg_kind) {
  m_reg_kind = reg_kind;
}

bool DWARFExpression::IsLocationList() const {
  return bool(m_loclist_addresses);
}

namespace {
/// Implement enough of the DWARFObject interface in order to be able to call
/// DWARFLocationTable::dumpLocationList. We don't have access to a real
/// DWARFObject here because DWARFExpression is used in non-DWARF scenarios too.
class DummyDWARFObject final: public llvm::DWARFObject {
public:
  DummyDWARFObject(bool IsLittleEndian) : IsLittleEndian(IsLittleEndian) {}

  bool isLittleEndian() const override { return IsLittleEndian; }

  llvm::Optional<llvm::RelocAddrEntry> find(const llvm::DWARFSection &Sec,
                                            uint64_t Pos) const override {
    return llvm::None;
  }
private:
  bool IsLittleEndian;
};
}

void DWARFExpression::GetDescription(Stream *s, lldb::DescriptionLevel level,
                                     addr_t location_list_base_addr,
                                     ABI *abi) const {
  if (IsLocationList()) {
    // We have a location list
    lldb::offset_t offset = 0;
    std::unique_ptr<llvm::DWARFLocationTable> loctable_up =
        m_dwarf_cu->GetLocationTable(m_data);

    llvm::MCRegisterInfo *MRI = abi ? &abi->GetMCRegisterInfo() : nullptr;
    llvm::DIDumpOptions DumpOpts;
    DumpOpts.RecoverableErrorHandler = [&](llvm::Error E) {
      s->AsRawOstream() << "error: " << toString(std::move(E));
    };
    loctable_up->dumpLocationList(
        &offset, s->AsRawOstream(),
        llvm::object::SectionedAddress{m_loclist_addresses->cu_file_addr}, MRI,
        DummyDWARFObject(m_data.GetByteOrder() == eByteOrderLittle), nullptr,
        DumpOpts, s->GetIndentLevel() + 2);
  } else {
    // We have a normal location that contains DW_OP location opcodes
    DumpLocation(s, m_data, level, abi);
  }
}

/// Return the length in bytes of the set of operands for \p op. No guarantees
/// are made on the state of \p data after this call.
static offset_t GetOpcodeDataSize(const DataExtractor &data,
                                  const lldb::offset_t data_offset,
                                  const uint8_t op) {
  lldb::offset_t offset = data_offset;
  switch (op) {
  case DW_OP_addr:
  case DW_OP_call_ref: // 0x9a 1 address sized offset of DIE (DWARF3)
    return data.GetAddressByteSize();

  // Opcodes with no arguments
  case DW_OP_deref:                // 0x06
  case DW_OP_dup:                  // 0x12
  case DW_OP_drop:                 // 0x13
  case DW_OP_over:                 // 0x14
  case DW_OP_swap:                 // 0x16
  case DW_OP_rot:                  // 0x17
  case DW_OP_xderef:               // 0x18
  case DW_OP_abs:                  // 0x19
  case DW_OP_and:                  // 0x1a
  case DW_OP_div:                  // 0x1b
  case DW_OP_minus:                // 0x1c
  case DW_OP_mod:                  // 0x1d
  case DW_OP_mul:                  // 0x1e
  case DW_OP_neg:                  // 0x1f
  case DW_OP_not:                  // 0x20
  case DW_OP_or:                   // 0x21
  case DW_OP_plus:                 // 0x22
  case DW_OP_shl:                  // 0x24
  case DW_OP_shr:                  // 0x25
  case DW_OP_shra:                 // 0x26
  case DW_OP_xor:                  // 0x27
  case DW_OP_eq:                   // 0x29
  case DW_OP_ge:                   // 0x2a
  case DW_OP_gt:                   // 0x2b
  case DW_OP_le:                   // 0x2c
  case DW_OP_lt:                   // 0x2d
  case DW_OP_ne:                   // 0x2e
  case DW_OP_lit0:                 // 0x30
  case DW_OP_lit1:                 // 0x31
  case DW_OP_lit2:                 // 0x32
  case DW_OP_lit3:                 // 0x33
  case DW_OP_lit4:                 // 0x34
  case DW_OP_lit5:                 // 0x35
  case DW_OP_lit6:                 // 0x36
  case DW_OP_lit7:                 // 0x37
  case DW_OP_lit8:                 // 0x38
  case DW_OP_lit9:                 // 0x39
  case DW_OP_lit10:                // 0x3A
  case DW_OP_lit11:                // 0x3B
  case DW_OP_lit12:                // 0x3C
  case DW_OP_lit13:                // 0x3D
  case DW_OP_lit14:                // 0x3E
  case DW_OP_lit15:                // 0x3F
  case DW_OP_lit16:                // 0x40
  case DW_OP_lit17:                // 0x41
  case DW_OP_lit18:                // 0x42
  case DW_OP_lit19:                // 0x43
  case DW_OP_lit20:                // 0x44
  case DW_OP_lit21:                // 0x45
  case DW_OP_lit22:                // 0x46
  case DW_OP_lit23:                // 0x47
  case DW_OP_lit24:                // 0x48
  case DW_OP_lit25:                // 0x49
  case DW_OP_lit26:                // 0x4A
  case DW_OP_lit27:                // 0x4B
  case DW_OP_lit28:                // 0x4C
  case DW_OP_lit29:                // 0x4D
  case DW_OP_lit30:                // 0x4E
  case DW_OP_lit31:                // 0x4f
  case DW_OP_reg0:                 // 0x50
  case DW_OP_reg1:                 // 0x51
  case DW_OP_reg2:                 // 0x52
  case DW_OP_reg3:                 // 0x53
  case DW_OP_reg4:                 // 0x54
  case DW_OP_reg5:                 // 0x55
  case DW_OP_reg6:                 // 0x56
  case DW_OP_reg7:                 // 0x57
  case DW_OP_reg8:                 // 0x58
  case DW_OP_reg9:                 // 0x59
  case DW_OP_reg10:                // 0x5A
  case DW_OP_reg11:                // 0x5B
  case DW_OP_reg12:                // 0x5C
  case DW_OP_reg13:                // 0x5D
  case DW_OP_reg14:                // 0x5E
  case DW_OP_reg15:                // 0x5F
  case DW_OP_reg16:                // 0x60
  case DW_OP_reg17:                // 0x61
  case DW_OP_reg18:                // 0x62
  case DW_OP_reg19:                // 0x63
  case DW_OP_reg20:                // 0x64
  case DW_OP_reg21:                // 0x65
  case DW_OP_reg22:                // 0x66
  case DW_OP_reg23:                // 0x67
  case DW_OP_reg24:                // 0x68
  case DW_OP_reg25:                // 0x69
  case DW_OP_reg26:                // 0x6A
  case DW_OP_reg27:                // 0x6B
  case DW_OP_reg28:                // 0x6C
  case DW_OP_reg29:                // 0x6D
  case DW_OP_reg30:                // 0x6E
  case DW_OP_reg31:                // 0x6F
  case DW_OP_nop:                  // 0x96
  case DW_OP_push_object_address:  // 0x97 DWARF3
  case DW_OP_form_tls_address:     // 0x9b DWARF3
  case DW_OP_call_frame_cfa:       // 0x9c DWARF3
  case DW_OP_stack_value:          // 0x9f DWARF4
  case DW_OP_GNU_push_tls_address: // 0xe0 GNU extension
    return 0;

  // Opcodes with a single 1 byte arguments
  case DW_OP_const1u:     // 0x08 1 1-byte constant
  case DW_OP_const1s:     // 0x09 1 1-byte constant
  case DW_OP_pick:        // 0x15 1 1-byte stack index
  case DW_OP_deref_size:  // 0x94 1 1-byte size of data retrieved
  case DW_OP_xderef_size: // 0x95 1 1-byte size of data retrieved
    return 1;

  // Opcodes with a single 2 byte arguments
  case DW_OP_const2u: // 0x0a 1 2-byte constant
  case DW_OP_const2s: // 0x0b 1 2-byte constant
  case DW_OP_skip:    // 0x2f 1 signed 2-byte constant
  case DW_OP_bra:     // 0x28 1 signed 2-byte constant
  case DW_OP_call2:   // 0x98 1 2-byte offset of DIE (DWARF3)
    return 2;

  // Opcodes with a single 4 byte arguments
  case DW_OP_const4u: // 0x0c 1 4-byte constant
  case DW_OP_const4s: // 0x0d 1 4-byte constant
  case DW_OP_call4:   // 0x99 1 4-byte offset of DIE (DWARF3)
    return 4;

  // Opcodes with a single 8 byte arguments
  case DW_OP_const8u: // 0x0e 1 8-byte constant
  case DW_OP_const8s: // 0x0f 1 8-byte constant
    return 8;

  // All opcodes that have a single ULEB (signed or unsigned) argument
  case DW_OP_addrx:           // 0xa1 1 ULEB128 index
  case DW_OP_constu:          // 0x10 1 ULEB128 constant
  case DW_OP_consts:          // 0x11 1 SLEB128 constant
  case DW_OP_plus_uconst:     // 0x23 1 ULEB128 addend
  case DW_OP_breg0:           // 0x70 1 ULEB128 register
  case DW_OP_breg1:           // 0x71 1 ULEB128 register
  case DW_OP_breg2:           // 0x72 1 ULEB128 register
  case DW_OP_breg3:           // 0x73 1 ULEB128 register
  case DW_OP_breg4:           // 0x74 1 ULEB128 register
  case DW_OP_breg5:           // 0x75 1 ULEB128 register
  case DW_OP_breg6:           // 0x76 1 ULEB128 register
  case DW_OP_breg7:           // 0x77 1 ULEB128 register
  case DW_OP_breg8:           // 0x78 1 ULEB128 register
  case DW_OP_breg9:           // 0x79 1 ULEB128 register
  case DW_OP_breg10:          // 0x7a 1 ULEB128 register
  case DW_OP_breg11:          // 0x7b 1 ULEB128 register
  case DW_OP_breg12:          // 0x7c 1 ULEB128 register
  case DW_OP_breg13:          // 0x7d 1 ULEB128 register
  case DW_OP_breg14:          // 0x7e 1 ULEB128 register
  case DW_OP_breg15:          // 0x7f 1 ULEB128 register
  case DW_OP_breg16:          // 0x80 1 ULEB128 register
  case DW_OP_breg17:          // 0x81 1 ULEB128 register
  case DW_OP_breg18:          // 0x82 1 ULEB128 register
  case DW_OP_breg19:          // 0x83 1 ULEB128 register
  case DW_OP_breg20:          // 0x84 1 ULEB128 register
  case DW_OP_breg21:          // 0x85 1 ULEB128 register
  case DW_OP_breg22:          // 0x86 1 ULEB128 register
  case DW_OP_breg23:          // 0x87 1 ULEB128 register
  case DW_OP_breg24:          // 0x88 1 ULEB128 register
  case DW_OP_breg25:          // 0x89 1 ULEB128 register
  case DW_OP_breg26:          // 0x8a 1 ULEB128 register
  case DW_OP_breg27:          // 0x8b 1 ULEB128 register
  case DW_OP_breg28:          // 0x8c 1 ULEB128 register
  case DW_OP_breg29:          // 0x8d 1 ULEB128 register
  case DW_OP_breg30:          // 0x8e 1 ULEB128 register
  case DW_OP_breg31:          // 0x8f 1 ULEB128 register
  case DW_OP_regx:            // 0x90 1 ULEB128 register
  case DW_OP_fbreg:           // 0x91 1 SLEB128 offset
  case DW_OP_piece:           // 0x93 1 ULEB128 size of piece addressed
  case DW_OP_GNU_addr_index:  // 0xfb 1 ULEB128 index
  case DW_OP_GNU_const_index: // 0xfc 1 ULEB128 index
    data.Skip_LEB128(&offset);
    return offset - data_offset;

  // All opcodes that have a 2 ULEB (signed or unsigned) arguments
  case DW_OP_bregx:     // 0x92 2 ULEB128 register followed by SLEB128 offset
  case DW_OP_bit_piece: // 0x9d ULEB128 bit size, ULEB128 bit offset (DWARF3);
    data.Skip_LEB128(&offset);
    data.Skip_LEB128(&offset);
    return offset - data_offset;

  case DW_OP_implicit_value: // 0x9e ULEB128 size followed by block of that size
                             // (DWARF4)
  {
    uint64_t block_len = data.Skip_LEB128(&offset);
    offset += block_len;
    return offset - data_offset;
  }

  case DW_OP_GNU_entry_value:
  case DW_OP_entry_value: // 0xa3 ULEB128 size + variable-length block
  {
    uint64_t subexpr_len = data.GetULEB128(&offset);
    return (offset - data_offset) + subexpr_len;
  }

  default:
    break;
  }
  return LLDB_INVALID_OFFSET;
}

lldb::addr_t DWARFExpression::GetLocation_DW_OP_addr(uint32_t op_addr_idx,
                                                     bool &error) const {
  error = false;
  if (IsLocationList())
    return LLDB_INVALID_ADDRESS;
  lldb::offset_t offset = 0;
  uint32_t curr_op_addr_idx = 0;
  while (m_data.ValidOffset(offset)) {
    const uint8_t op = m_data.GetU8(&offset);

    if (op == DW_OP_addr) {
      const lldb::addr_t op_file_addr = m_data.GetAddress(&offset);
      if (curr_op_addr_idx == op_addr_idx)
        return op_file_addr;
      else
        ++curr_op_addr_idx;
    } else if (op == DW_OP_GNU_addr_index || op == DW_OP_addrx) {
      uint64_t index = m_data.GetULEB128(&offset);
      if (curr_op_addr_idx == op_addr_idx) {
        if (!m_dwarf_cu) {
          error = true;
          break;
        }

        return ReadAddressFromDebugAddrSection(m_dwarf_cu, index);
      } else
        ++curr_op_addr_idx;
    } else {
      const offset_t op_arg_size = GetOpcodeDataSize(m_data, offset, op);
      if (op_arg_size == LLDB_INVALID_OFFSET) {
        error = true;
        break;
      }
      offset += op_arg_size;
    }
  }
  return LLDB_INVALID_ADDRESS;
}

bool DWARFExpression::Update_DW_OP_addr(lldb::addr_t file_addr) {
  if (IsLocationList())
    return false;
  lldb::offset_t offset = 0;
  while (m_data.ValidOffset(offset)) {
    const uint8_t op = m_data.GetU8(&offset);

    if (op == DW_OP_addr) {
      const uint32_t addr_byte_size = m_data.GetAddressByteSize();
      // We have to make a copy of the data as we don't know if this data is
      // from a read only memory mapped buffer, so we duplicate all of the data
      // first, then modify it, and if all goes well, we then replace the data
      // for this expression

      // So first we copy the data into a heap buffer
      std::unique_ptr<DataBufferHeap> head_data_up(
          new DataBufferHeap(m_data.GetDataStart(), m_data.GetByteSize()));

      // Make en encoder so we can write the address into the buffer using the
      // correct byte order (endianness)
      DataEncoder encoder(head_data_up->GetBytes(), head_data_up->GetByteSize(),
                          m_data.GetByteOrder(), addr_byte_size);

      // Replace the address in the new buffer
      if (encoder.PutUnsigned(offset, addr_byte_size, file_addr) == UINT32_MAX)
        return false;

      // All went well, so now we can reset the data using a shared pointer to
      // the heap data so "m_data" will now correctly manage the heap data.
      m_data.SetData(DataBufferSP(head_data_up.release()));
      return true;
    } else {
      const offset_t op_arg_size = GetOpcodeDataSize(m_data, offset, op);
      if (op_arg_size == LLDB_INVALID_OFFSET)
        break;
      offset += op_arg_size;
    }
  }
  return false;
}

bool DWARFExpression::ContainsThreadLocalStorage() const {
  // We are assuming for now that any thread local variable will not have a
  // location list. This has been true for all thread local variables we have
  // seen so far produced by any compiler.
  if (IsLocationList())
    return false;
  lldb::offset_t offset = 0;
  while (m_data.ValidOffset(offset)) {
    const uint8_t op = m_data.GetU8(&offset);

    if (op == DW_OP_form_tls_address || op == DW_OP_GNU_push_tls_address)
      return true;
    const offset_t op_arg_size = GetOpcodeDataSize(m_data, offset, op);
    if (op_arg_size == LLDB_INVALID_OFFSET)
      return false;
    else
      offset += op_arg_size;
  }
  return false;
}
bool DWARFExpression::LinkThreadLocalStorage(
    lldb::ModuleSP new_module_sp,
    std::function<lldb::addr_t(lldb::addr_t file_addr)> const
        &link_address_callback) {
  // We are assuming for now that any thread local variable will not have a
  // location list. This has been true for all thread local variables we have
  // seen so far produced by any compiler.
  if (IsLocationList())
    return false;

  const uint32_t addr_byte_size = m_data.GetAddressByteSize();
  // We have to make a copy of the data as we don't know if this data is from a
  // read only memory mapped buffer, so we duplicate all of the data first,
  // then modify it, and if all goes well, we then replace the data for this
  // expression

  // So first we copy the data into a heap buffer
  std::shared_ptr<DataBufferHeap> heap_data_sp(
      new DataBufferHeap(m_data.GetDataStart(), m_data.GetByteSize()));

  // Make en encoder so we can write the address into the buffer using the
  // correct byte order (endianness)
  DataEncoder encoder(heap_data_sp->GetBytes(), heap_data_sp->GetByteSize(),
                      m_data.GetByteOrder(), addr_byte_size);

  lldb::offset_t offset = 0;
  lldb::offset_t const_offset = 0;
  lldb::addr_t const_value = 0;
  size_t const_byte_size = 0;
  while (m_data.ValidOffset(offset)) {
    const uint8_t op = m_data.GetU8(&offset);

    bool decoded_data = false;
    switch (op) {
    case DW_OP_const4u:
      // Remember the const offset in case we later have a
      // DW_OP_form_tls_address or DW_OP_GNU_push_tls_address
      const_offset = offset;
      const_value = m_data.GetU32(&offset);
      decoded_data = true;
      const_byte_size = 4;
      break;

    case DW_OP_const8u:
      // Remember the const offset in case we later have a
      // DW_OP_form_tls_address or DW_OP_GNU_push_tls_address
      const_offset = offset;
      const_value = m_data.GetU64(&offset);
      decoded_data = true;
      const_byte_size = 8;
      break;

    case DW_OP_form_tls_address:
    case DW_OP_GNU_push_tls_address:
      // DW_OP_form_tls_address and DW_OP_GNU_push_tls_address must be preceded
      // by a file address on the stack. We assume that DW_OP_const4u or
      // DW_OP_const8u is used for these values, and we check that the last
      // opcode we got before either of these was DW_OP_const4u or
      // DW_OP_const8u. If so, then we can link the value accodingly. For
      // Darwin, the value in the DW_OP_const4u or DW_OP_const8u is the file
      // address of a structure that contains a function pointer, the pthread
      // key and the offset into the data pointed to by the pthread key. So we
      // must link this address and also set the module of this expression to
      // the new_module_sp so we can resolve the file address correctly
      if (const_byte_size > 0) {
        lldb::addr_t linked_file_addr = link_address_callback(const_value);
        if (linked_file_addr == LLDB_INVALID_ADDRESS)
          return false;
        // Replace the address in the new buffer
        if (encoder.PutUnsigned(const_offset, const_byte_size,
                                linked_file_addr) == UINT32_MAX)
          return false;
      }
      break;

    default:
      const_offset = 0;
      const_value = 0;
      const_byte_size = 0;
      break;
    }

    if (!decoded_data) {
      const offset_t op_arg_size = GetOpcodeDataSize(m_data, offset, op);
      if (op_arg_size == LLDB_INVALID_OFFSET)
        return false;
      else
        offset += op_arg_size;
    }
  }

  // If we linked the TLS address correctly, update the module so that when the
  // expression is evaluated it can resolve the file address to a load address
  // and read the
  // TLS data
  m_module_wp = new_module_sp;
  m_data.SetData(heap_data_sp);
  return true;
}

bool DWARFExpression::LocationListContainsAddress(addr_t func_load_addr,
                                                  lldb::addr_t addr) const {
  if (func_load_addr == LLDB_INVALID_ADDRESS || addr == LLDB_INVALID_ADDRESS)
    return false;

  if (!IsLocationList())
    return false;

  return GetLocationExpression(func_load_addr, addr) != llvm::None;
}

bool DWARFExpression::DumpLocationForAddress(Stream *s,
                                             lldb::DescriptionLevel level,
                                             addr_t func_load_addr,
                                             addr_t address, ABI *abi) {
  if (!IsLocationList()) {
    DumpLocation(s, m_data, level, abi);
    return true;
  }
  if (llvm::Optional<DataExtractor> expr =
          GetLocationExpression(func_load_addr, address)) {
    DumpLocation(s, *expr, level, abi);
    return true;
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

bool DWARFExpression::Evaluate(ExecutionContextScope *exe_scope,
                               lldb::addr_t loclist_base_load_addr,
                               const Value *initial_value_ptr,
                               const Value *object_address_ptr, Value &result,
                               Status *error_ptr) const {
  ExecutionContext exe_ctx(exe_scope);
  return Evaluate(&exe_ctx, nullptr, loclist_base_load_addr, initial_value_ptr,
                  object_address_ptr, result, error_ptr);
}

bool DWARFExpression::Evaluate(ExecutionContext *exe_ctx,
                               RegisterContext *reg_ctx,
                               lldb::addr_t func_load_addr,
                               const Value *initial_value_ptr,
                               const Value *object_address_ptr, Value &result,
                               Status *error_ptr) const {
  ModuleSP module_sp = m_module_wp.lock();

  // Use the DWARF expression evaluator registered for this module (or
  // DWARFEvaluator by default).
  DWARFEvaluatorFactory *evaluator_factory =
      module_sp->GetDWARFExpressionEvaluatorFactory();
  std::unique_ptr<DWARFEvaluator> evaluator =
      evaluator_factory->CreateDWARFEvaluator(
          *this, exe_ctx, reg_ctx, initial_value_ptr, object_address_ptr);

  if (IsLocationList()) {
    addr_t pc;
    StackFrame *frame = nullptr;
    if (reg_ctx)
      pc = reg_ctx->GetPC();
    else {
      frame = exe_ctx->GetFramePtr();
      if (!frame)
        return false;
      RegisterContextSP reg_ctx_sp = frame->GetRegisterContext();
      if (!reg_ctx_sp)
        return false;
      pc = reg_ctx_sp->GetPC();
    }

    if (func_load_addr != LLDB_INVALID_ADDRESS) {
      if (pc == LLDB_INVALID_ADDRESS) {
        if (error_ptr)
          error_ptr->SetErrorString("Invalid PC in frame.");
        return false;
      }

      if (llvm::Optional<DataExtractor> expr =
              GetLocationExpression(func_load_addr, pc)) {
        return evaluator->Evaluate(*expr, result, error_ptr);
      }
    }
    if (error_ptr)
      error_ptr->SetErrorString("variable not available");
    return false;
  }

  // Not a location list, just a single expression.
  return evaluator->Evaluate(result, error_ptr);
}

bool DWARFExpression::Evaluate(
    ExecutionContext *exe_ctx, RegisterContext *reg_ctx,
    lldb::ModuleSP module_sp, const DataExtractor &opcodes,
    const DWARFUnit *dwarf_cu, const lldb::RegisterKind reg_kind,
    const Value *initial_value_ptr, const Value *object_address_ptr,
    Value &result, Status *error_ptr) {
  DWARFExpression expr(module_sp, opcodes, dwarf_cu);
  expr.SetRegisterKind(reg_kind);

  // Use the DWARF expression evaluator registered for this module (or
  // DWARFEvaluator by default).
  DWARFEvaluatorFactory *evaluator_factory =
      module_sp->GetDWARFExpressionEvaluatorFactory();
  std::unique_ptr<DWARFEvaluator> evaluator =
      evaluator_factory->CreateDWARFEvaluator(
          expr, exe_ctx, reg_ctx, initial_value_ptr, object_address_ptr);
  return evaluator->Evaluate(result, error_ptr);
}

static DataExtractor ToDataExtractor(const llvm::DWARFLocationExpression &loc,
                                     ByteOrder byte_order, uint32_t addr_size) {
  auto buffer_sp =
      std::make_shared<DataBufferHeap>(loc.Expr.data(), loc.Expr.size());
  return DataExtractor(buffer_sp, byte_order, addr_size);
}

llvm::Optional<DataExtractor>
DWARFExpression::GetLocationExpression(addr_t load_function_start,
                                       addr_t addr) const {
  Log *log = GetLogIfAllCategoriesSet(LIBLLDB_LOG_EXPRESSIONS);

  std::unique_ptr<llvm::DWARFLocationTable> loctable_up =
      m_dwarf_cu->GetLocationTable(m_data);
  llvm::Optional<DataExtractor> result;
  uint64_t offset = 0;
  auto lookup_addr =
      [&](uint32_t index) -> llvm::Optional<llvm::object::SectionedAddress> {
    addr_t address = ReadAddressFromDebugAddrSection(m_dwarf_cu, index);
    if (address == LLDB_INVALID_ADDRESS)
      return llvm::None;
    return llvm::object::SectionedAddress{address};
  };
  auto process_list = [&](llvm::Expected<llvm::DWARFLocationExpression> loc) {
    if (!loc) {
      LLDB_LOG_ERROR(log, loc.takeError(), "{0}");
      return true;
    }
    if (loc->Range) {
      // This relocates low_pc and high_pc by adding the difference between the
      // function file address, and the actual address it is loaded in memory.
      addr_t slide = load_function_start - m_loclist_addresses->func_file_addr;
      loc->Range->LowPC += slide;
      loc->Range->HighPC += slide;

      if (loc->Range->LowPC <= addr && addr < loc->Range->HighPC)
        result = ToDataExtractor(*loc, m_data.GetByteOrder(),
                                 m_data.GetAddressByteSize());
    }
    return !result;
  };
  llvm::Error E = loctable_up->visitAbsoluteLocationList(
      offset, llvm::object::SectionedAddress{m_loclist_addresses->cu_file_addr},
      lookup_addr, process_list);
  if (E)
    LLDB_LOG_ERROR(log, std::move(E), "{0}");
  return result;
}

bool DWARFExpression::MatchesOperand(StackFrame &frame,
                                     const Instruction::Operand &operand) {
  using namespace OperandMatchers;

  RegisterContextSP reg_ctx_sp = frame.GetRegisterContext();
  if (!reg_ctx_sp) {
    return false;
  }

  DataExtractor opcodes;
  if (IsLocationList()) {
    SymbolContext sc = frame.GetSymbolContext(eSymbolContextFunction);
    if (!sc.function)
      return false;

    addr_t load_function_start =
        sc.function->GetAddressRange().GetBaseAddress().GetFileAddress();
    if (load_function_start == LLDB_INVALID_ADDRESS)
      return false;

    addr_t pc = frame.GetFrameCodeAddress().GetLoadAddress(
        frame.CalculateTarget().get());

    if (llvm::Optional<DataExtractor> expr = GetLocationExpression(load_function_start, pc))
      opcodes = std::move(*expr);
    else
      return false;
  } else
    opcodes = m_data;


  lldb::offset_t op_offset = 0;
  uint8_t opcode = opcodes.GetU8(&op_offset);

  if (opcode == DW_OP_fbreg) {
    int64_t offset = opcodes.GetSLEB128(&op_offset);

    DWARFExpression *fb_expr = frame.GetFrameBaseExpression(nullptr);
    if (!fb_expr) {
      return false;
    }

    auto recurse = [&frame, fb_expr](const Instruction::Operand &child) {
      return fb_expr->MatchesOperand(frame, child);
    };

    if (!offset &&
        MatchUnaryOp(MatchOpType(Instruction::Operand::Type::Dereference),
                     recurse)(operand)) {
      return true;
    }

    return MatchUnaryOp(
        MatchOpType(Instruction::Operand::Type::Dereference),
        MatchBinaryOp(MatchOpType(Instruction::Operand::Type::Sum),
                      MatchImmOp(offset), recurse))(operand);
  }

  bool dereference = false;
  const RegisterInfo *reg = nullptr;
  int64_t offset = 0;

  if (opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31) {
    reg = reg_ctx_sp->GetRegisterInfo(m_reg_kind, opcode - DW_OP_reg0);
  } else if (opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31) {
    offset = opcodes.GetSLEB128(&op_offset);
    reg = reg_ctx_sp->GetRegisterInfo(m_reg_kind, opcode - DW_OP_breg0);
  } else if (opcode == DW_OP_regx) {
    uint32_t reg_num = static_cast<uint32_t>(opcodes.GetULEB128(&op_offset));
    reg = reg_ctx_sp->GetRegisterInfo(m_reg_kind, reg_num);
  } else if (opcode == DW_OP_bregx) {
    uint32_t reg_num = static_cast<uint32_t>(opcodes.GetULEB128(&op_offset));
    offset = opcodes.GetSLEB128(&op_offset);
    reg = reg_ctx_sp->GetRegisterInfo(m_reg_kind, reg_num);
  } else {
    return false;
  }

  if (!reg) {
    return false;
  }

  if (dereference) {
    if (!offset &&
        MatchUnaryOp(MatchOpType(Instruction::Operand::Type::Dereference),
                     MatchRegOp(*reg))(operand)) {
      return true;
    }

    return MatchUnaryOp(
        MatchOpType(Instruction::Operand::Type::Dereference),
        MatchBinaryOp(MatchOpType(Instruction::Operand::Type::Sum),
                      MatchRegOp(*reg),
                      MatchImmOp(offset)))(operand);
  } else {
    return MatchRegOp(*reg)(operand);
  }
}
