///
/// Copyright (C) 2023, Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_PLUGINS_ThreadExecutionDetector_H
#define S2E_PLUGINS_ThreadExecutionDetector_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>

#include <s2e/monitors/support/thread_execution_detector.h>

#include "ITracker.h"

namespace s2e {
namespace plugins {

class OSMonitor;

///
/// @brief This class allows clients plugins to instrument code running
/// inside threads of interest.
///
/// This plugin can only be configured from guest code. The guest header file
/// provides APIs to enable/disable tracking for the thread they are called from
/// as well as enable/disable kernel tracking in the context of that thread.
///
class ThreadExecutionDetector : public Plugin, public IPluginInvoker, public ITracker {
    S2E_PLUGIN

public:
    ThreadExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isTrackedPc(S2EExecutionState *state, uint64_t pc);
    bool isTrackingConfigured(S2EExecutionState *state);

private:
    OSMonitor *m_monitor;

    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ThreadExecutionDetector_H
