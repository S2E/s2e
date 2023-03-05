///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
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

#ifndef S2E__INSTRUCTION_COUNTER_H
#define S2E__INSTRUCTION_COUNTER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <unordered_set>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ITracker.h>

#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

enum S2E_ICOUNT_COMMANDS { ICOUNT_RESET, ICOUNT_GET };

struct S2E_ICOUNT_COMMAND {
    enum S2E_ICOUNT_COMMANDS Command;
    union {
        uint64_t Count;
    };
} __attribute__((packed));

class ProcessExecutionDetector;
class ModuleMap;

class InstructionCounter : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
private:
    ExecutionTracer *m_tracer = nullptr;
    ITracker *m_tracker = nullptr;
    OSMonitor *m_monitor = nullptr;

public:
    InstructionCounter(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    void onConfigChange(S2EExecutionState *state);
    void writeData(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t count);

    void onMonitorLoad(S2EExecutionState *state);
    void onStateKill(S2EExecutionState *state);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTbExecuteStart(S2EExecutionState *state, uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);

    void onInstruction(S2EExecutionState *state, uint64_t pc);

    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onProcessOrThreadSwitch(S2EExecutionState *state);

    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
