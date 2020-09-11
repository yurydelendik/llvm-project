//===-- DWARFEvaluatorFactory.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Expression/DWARFEvaluatorFactory.h"
#include "lldb/Expression/DWARFEvaluator.h"

#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Value.h"
#include "lldb/Target/RegisterContext.h"

using namespace lldb;
using namespace lldb_private;

// PluginInterface protocol
lldb_private::ConstString DWARFEvaluatorFactory::GetPluginName() {
  static ConstString g_name("vendor-default");
  return g_name;
}

// FindPlugin
//
// Platforms can register a callback to use when creating DWARF expression
// evaluators to allow handling platform-specific DWARF codes.
std::unique_ptr<DWARFEvaluatorFactory>
DWARFEvaluatorFactory::FindPlugin(Module *module) {
  std::unique_ptr<DWARFEvaluatorFactory> instance_up;
  DWARFEvaluatorFactoryCreateInstance create_callback;

  for (size_t idx = 0;
       (create_callback =
            PluginManager::GetDWARFEvaluatorFactoryCreateCallbackAtIndex(
                idx)) != nullptr;
       ++idx) {
    instance_up.reset(create_callback(module));

    if (instance_up) {
      return instance_up;
    }
  }

  instance_up.reset(new DWARFEvaluatorFactory());
  return instance_up;
}

std::unique_ptr<DWARFEvaluator> DWARFEvaluatorFactory::CreateDWARFEvaluator(
    const DWARFExpression &dwarf_expression, ExecutionContext *exe_ctx,
    RegisterContext *reg_ctx, const Value *initial_value_ptr,
    const Value *object_address_ptr) {
  return std::make_unique<DWARFEvaluator>(dwarf_expression, exe_ctx, reg_ctx,
                                          initial_value_ptr,
                                          object_address_ptr);
}
