
add_lldb_library(lldbPluginProcessWasm PLUGIN
  ProcessWasm.cpp
  ThreadWasm.cpp
  UnwindWasm.cpp

  LINK_LIBS
    lldbCore
    ${LLDB_PLUGINS}
  LINK_COMPONENTS
    Support
  )
