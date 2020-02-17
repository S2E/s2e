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

#include "ExecutionTracer.h"
#include "ModuleTracing.h"

namespace s2e {
namespace plugins {

class ProcessExecutionDetector;
class ModuleMap;

class InstructionCounter : public Plugin {
    S2E_PLUGIN
private:
    ExecutionTracer *m_tracer;
    ProcessExecutionDetector *m_detector;

    ModuleTracing m_modules;

    sigc::connection m_tbConnection;

public:
    InstructionCounter(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    void onInitializationComplete(S2EExecutionState *state);
    void onStateKill(S2EExecutionState *state);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);

    void onInstruction(S2EExecutionState *state, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
