//===-- UnwindWasm.cpp ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UnwindWasm.h"
#include "Plugins/Process/gdb-remote/ThreadGDBRemote.h"
#include "Plugins/Process/wasm/ProcessWasm.h"
#include "Plugins/Process/wasm/ThreadWasm.h"

using namespace lldb;
using namespace lldb_private;
using namespace process_gdb_remote;
using namespace wasm;

class WasmGDBRemoteRegisterContext : public GDBRemoteRegisterContext {
public:
  WasmGDBRemoteRegisterContext(ThreadGDBRemote &thread,
                               uint32_t concrete_frame_idx,
                               GDBRemoteDynamicRegisterInfo &reg_info,
                               uint64_t pc)
      : GDBRemoteRegisterContext(thread, concrete_frame_idx, reg_info, false,
                                 false) {
    PrivateSetRegisterValue(0, pc);
  }
};

lldb::RegisterContextSP
UnwindWasm::DoCreateRegisterContextForFrame(lldb_private::StackFrame *frame) {
  if (m_frames.size() <= frame->GetFrameIndex()) {
    return lldb::RegisterContextSP();
  }

  ThreadSP thread = frame->GetThread();
  ThreadGDBRemote *gdb_thread = static_cast<ThreadGDBRemote *>(thread.get());
  ProcessWasm *wasm_process =
      static_cast<ProcessWasm *>(thread->GetProcess().get());
  std::shared_ptr<GDBRemoteRegisterContext> reg_ctx_sp =
      std::make_shared<WasmGDBRemoteRegisterContext>(
          *gdb_thread, frame->GetConcreteFrameIndex(),
          wasm_process->GetRegisterInfo(), m_frames[frame->GetFrameIndex()]);
  return reg_ctx_sp;
}

uint32_t UnwindWasm::DoGetFrameCount() {
  if (!m_unwind_complete) {
    m_unwind_complete = true;
    m_frames.clear();

    ThreadWasm &wasm_thread = static_cast<ThreadWasm &>(GetThread());
    if (!wasm_thread.GetWasmCallStack(m_frames))
      m_frames.clear();
  }
  return m_frames.size();
}

bool UnwindWasm::DoGetFrameInfoAtIndex(uint32_t frame_idx, lldb::addr_t &cfa,
                                       lldb::addr_t &pc,
                                       bool &behaves_like_zeroth_frame) {
  if (m_frames.size() == 0) {
    DoGetFrameCount();
  }

  if (frame_idx < m_frames.size()) {
    behaves_like_zeroth_frame = (frame_idx == 0);
    cfa = 0;
    pc = m_frames[frame_idx];
    return true;
  }
  return false;
}