//===-- WasmDWARFEvaluatorFactory.cpp -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "WasmDWARFEvaluatorFactory.h"
#include "WasmDWARFEvaluator.h"

#include "Plugins/ObjectFile/wasm/ObjectFileWasm.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::wasm;

LLDB_PLUGIN_DEFINE(WasmDWARFEvaluatorFactory)

void WasmDWARFEvaluatorFactory::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                GetPluginDescriptionStatic(), CreateInstance);
}

void WasmDWARFEvaluatorFactory::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

lldb_private::ConstString WasmDWARFEvaluatorFactory::GetPluginNameStatic() {
  static ConstString g_name("WASM");
  return g_name;
}

const char *WasmDWARFEvaluatorFactory::GetPluginDescriptionStatic() {
  return "DWARF expression evaluator factory for WASM.";
}

// CreateInstance
//
// Platforms can register a callback to use when creating DWARF expression
// evaluators to allow handling platform-specific DWARF codes.
DWARFEvaluatorFactory *
WasmDWARFEvaluatorFactory::CreateInstance(Module *module) {
  if (!module)
    return nullptr;

  ObjectFileWasm *obj_file =
      llvm::dyn_cast_or_null<ObjectFileWasm>(module->GetObjectFile());
  if (!obj_file)
    return nullptr;

  return new WasmDWARFEvaluatorFactory();
}

std::unique_ptr<DWARFEvaluator> WasmDWARFEvaluatorFactory::CreateDWARFEvaluator(
    const DWARFExpression &dwarf_expression, ExecutionContext *exe_ctx,
    RegisterContext *reg_ctx, const Value *initial_value_ptr,
    const Value *object_address_ptr) {
  return std::make_unique<WasmDWARFEvaluator>(dwarf_expression, exe_ctx,
                                              reg_ctx, initial_value_ptr,
                                              object_address_ptr);
}
