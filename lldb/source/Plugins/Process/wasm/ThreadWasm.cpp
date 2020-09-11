//===-- ThreadWasm.cpp ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ThreadWasm.h"

#include "ProcessWasm.h"
#include "UnwindWasm.h"
#include "lldb/Target/Target.h"

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::wasm;

Unwind &ThreadWasm::GetUnwinder() {
  if (!m_unwinder_up) {
    assert(CalculateTarget()->GetArchitecture().GetMachine() ==
           llvm::Triple::wasm32);
    m_unwinder_up.reset(new wasm::UnwindWasm(*this));
  }
  return *m_unwinder_up;
}

bool ThreadWasm::GetWasmCallStack(std::vector<lldb::addr_t> &call_stack_pcs) {
  ProcessSP process_sp(GetProcess());
  if (process_sp) {
    ProcessWasm *wasm_process = static_cast<ProcessWasm *>(process_sp.get());
    return wasm_process->GetWasmCallStack(GetID(), call_stack_pcs);
  }
  return false;
}
