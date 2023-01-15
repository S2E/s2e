///
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_PLUGINS_ProcessExecutionDetector_H
#define S2E_PLUGINS_ProcessExecutionDetector_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>

#include <s2e/monitors/support/process_execution_detector.h>

#include "ITracker.h"

namespace s2e {
namespace plugins {

class OSMonitor;

typedef llvm::DenseSet<uint64_t> TrackedPids;

///
/// @brief This class allows clients plugins to instrument code running
/// inside processes of interest.
///
/// This plugin can be configured from the lua file or dynamically from
/// the guest, using the APIs in the guest header file. It is possible
/// to enable/disable which PIDs are tracked at runtime.
///
class ProcessExecutionDetector : public Plugin, public IPluginInvoker, public ITracker {
    S2E_PLUGIN

public:
    ProcessExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isTrackingConfigured(S2EExecutionState *state);
    bool isTrackedPc(S2EExecutionState *state, uint64_t pc);
    bool isTrackedPid(S2EExecutionState *state, uint64_t pid);
    bool isTrackedModule(const std::string &module) const;
    bool isTrackedPc(S2EExecutionState *state, uint64_t pc, bool checkCpl);

    void trackPid(S2EExecutionState *state, uint64_t pid);

    sigc::signal<void, S2EExecutionState *> onMonitorLoad;
    sigc::signal<void, S2EExecutionState *> onAllProcessesTerminated;

    const TrackedPids &getTrackedPids(S2EExecutionState *state) const;

private:
    typedef std::unordered_set<std::string> StringSet;

    OSMonitor *m_monitor;

    StringSet m_trackedModules;

    bool m_trackKernel = false;

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onMonitorLoadCb(S2EExecutionState *state);

    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ProcessExecutionDetector_H
