add_lldb_library(lldbPluginWasmDWARFEvaluatorFactory PLUGIN
  WasmDWARFEvaluator.cpp
  WasmDWARFEvaluatorFactory.cpp

  LINK_LIBS
    lldbCore
    lldbHost
    lldbSymbol
    lldbPluginObjectFileWasm
  )
