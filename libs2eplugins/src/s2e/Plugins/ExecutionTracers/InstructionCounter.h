///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
