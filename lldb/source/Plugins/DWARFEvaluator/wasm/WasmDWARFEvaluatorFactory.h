//===-- WasmDWARFEvaluatorFactory.h -----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATORFACTORY_H
#define LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATORFACTORY_H

#include "lldb/Expression/DWARFEvaluatorFactory.h"

namespace lldb_private {
namespace wasm {

/// \class WasmDWARFEvaluatorFactory creates DWARF evaluators specialized to
///  manage DWARF-specific opcodes.
class WasmDWARFEvaluatorFactory : public DWARFEvaluatorFactory {
public:
  static void Initialize();
  static void Terminate();
  static lldb_private::ConstString GetPluginNameStatic();
  static const char *GetPluginDescriptionStatic();

  static lldb_private::DWARFEvaluatorFactory *CreateInstance(Module *module);

  /// PluginInterface protocol.
  /// \{
  lldb_private::ConstString GetPluginName() override {
    return GetPluginNameStatic();
  }
  uint32_t GetPluginVersion() override { return 1; }
  /// \}

  WasmDWARFEvaluatorFactory() {}

  /// DWARFEvaluatorFactory protocol.
  /// \{
  std::unique_ptr<DWARFEvaluator>
  CreateDWARFEvaluator(const DWARFExpression &dwarf_expression,
                       ExecutionContext *exe_ctx, RegisterContext *reg_ctx,
                       const Value *initial_value_ptr,
                       const Value *object_address_ptr) override;
  /// \}

private:
  WasmDWARFEvaluatorFactory(const WasmDWARFEvaluatorFactory &) = delete;
  const WasmDWARFEvaluatorFactory &
  operator=(const WasmDWARFEvaluatorFactory &) = delete;
};

} // namespace wasm
} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_DWARFEVALUATOR_WASM_WASMDWARFEVALUATORFACTORY_H
