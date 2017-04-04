///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E__INSTRUCTION_COUNTER_H
#define S2E__INSTRUCTION_COUNTER_H

#include <fstream>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <set>

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

class InstructionCounter : public Plugin {
    S2E_PLUGIN
private:
    ModuleExecutionDetector *m_executionDetector;
    ExecutionTracer *m_executionTracer;

    TranslationBlock *m_tb;
    sigc::connection m_tbConnection;

public:
    InstructionCounter(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    void startCounter();

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                               TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);

    void onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                   TranslationBlock *tb, uint64_t endPc, bool staticTarget, uint64_t targetPc);

    void onTraceTb(S2EExecutionState *state, uint64_t pc);
    void onTraceInstruction(S2EExecutionState *state, uint64_t pc);
};

class InstructionCounterState : public PluginState {
private:
    uint64_t m_iCount;
    uint64_t m_lastTbPc;

public:
    InstructionCounterState();
    InstructionCounterState(S2EExecutionState *s, Plugin *p);
    virtual ~InstructionCounterState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class InstructionCounter;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
