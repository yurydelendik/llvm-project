//===-- WasmDWARFEvaluator.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATOR_H
#define LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATOR_H

#include "lldb/Expression/DWARFEvaluator.h"
#include "lldb/lldb-private.h"

namespace lldb_private {
namespace wasm {

/// \class WasmDWARFEvaluator evaluates DWARF expressions in the context of a
///  WebAssembly process.
///
class WasmDWARFEvaluator : public DWARFEvaluator {
public:
  WasmDWARFEvaluator(const DWARFExpression &dwarf_expression,
                     ExecutionContext *exe_ctx, RegisterContext *reg_ctx,
                     const Value *initial_value_ptr,
                     const Value *object_address_ptr)
      : DWARFEvaluator(dwarf_expression, exe_ctx, reg_ctx, initial_value_ptr,
                       object_address_ptr) {}

  /// DWARFEvaluator protocol.
  /// \{
  bool Evaluate(const uint8_t op, Process *process, StackFrame *frame,
                std::vector<Value> &stack, const DataExtractor &opcodes,
                lldb::offset_t &offset, Value &pieces,
                uint64_t &op_piece_offset, Log *log,
                Status *error_ptr) override;
  /// \}

private:
  WasmDWARFEvaluator(const WasmDWARFEvaluator &) = delete;
  const WasmDWARFEvaluator &operator=(const WasmDWARFEvaluator &) = delete;
};

} // namespace wasm
} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATOR_H
