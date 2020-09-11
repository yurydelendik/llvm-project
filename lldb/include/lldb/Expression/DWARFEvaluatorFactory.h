//===-- DWARFEvaluatorFactory.h ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_EXPRESSION_DWARFEVALUATORFACTORY_H
#define LLDB_EXPRESSION_DWARFEVALUATORFACTORY_H

#include "lldb/Core/PluginInterface.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/lldb-private.h"

class DWARFUnit;

namespace lldb_private {

class DWARFEvaluator;
class DWARFExpression;

/// \class DWARFEvaluatorFactory DWARFEvaluatorFactory.h
/// "lldb/Expression/DWARFEvaluatorFactory.h" Factory class that allows the
/// registration of platform-specific DWARF expression evaluators, used to
/// handle platform-specific DWARF opcodes.
class DWARFEvaluatorFactory : public PluginInterface {
public:
  static std::unique_ptr<DWARFEvaluatorFactory> FindPlugin(Module *module);

  /// PluginInterface protocol.
  /// \{
  ConstString GetPluginName() override;

  uint32_t GetPluginVersion() override { return 1; }
  /// \}

  DWARFEvaluatorFactory() {}

  /// DWARFEvaluatorFactory protocol.
  /// \{
  virtual std::unique_ptr<DWARFEvaluator>
  CreateDWARFEvaluator(const DWARFExpression &dwarf_expression,
                       ExecutionContext *exe_ctx, RegisterContext *reg_ctx,
                       const Value *initial_value_ptr,
                       const Value *object_address_ptr);
  /// \}

private:
  DWARFEvaluatorFactory(const DWARFEvaluatorFactory &) = delete;
  const DWARFEvaluatorFactory &
  operator=(const DWARFEvaluatorFactory &) = delete;
};

} // namespace lldb_private

#endif // LLDB_EXPRESSION_DWARFEVALUATORFACTORY_H
