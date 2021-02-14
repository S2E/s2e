///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#ifndef S2E_PLUGINS_UserSpaceTracer_H
#define S2E_PLUGINS_UserSpaceTracer_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {

struct ThreadDescriptor;

namespace plugins {

class OSMonitor;
class WindowsMonitor;
class ExecutionTracer;
class MemoryTracer;
struct S2E_WINMON2_ACCESS_FAULT;

class UserSpaceTracer : public Plugin {
    S2E_PLUGIN
public:
    UserSpaceTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void startTracing(S2EExecutionState *state, uint64_t pid);
    void startTracing(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t maxTraceItems = -1);
    void stopTracing(S2EExecutionState *state, uint64_t pid);
    void stopTracing(S2EExecutionState *state, uint64_t pid, uint64_t tid);

private:
    WindowsMonitor *m_monitor;
    MemoryTracer *m_memoryTracer;
    ExecutionTracer *m_tracer;

    sigc::connection m_tbComplete;
    sigc::connection m_tbStart;

    bool m_traceExecution;
    bool m_traceTranslation;
    bool m_traceMemory;

    std::unordered_set<std::string> m_processNames;

    void onMonitorLoad(S2EExecutionState *state);

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &imageName);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onProcessOrThreadSwitch(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *current, S2EExecutionState *next);
    void updateInstrumentation(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc);

    void onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    void onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_UserSpaceTracer_H
