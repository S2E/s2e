///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_TBTRACER_H
#define S2E_PLUGINS_TBTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include "ExecutionTracer.h"
#include "TraceEntries.h"

namespace s2e {
namespace plugins {

#define TB_TRACER_OPCODE 0xAD

class TranslationBlockTracer : public Plugin {
    S2E_PLUGIN
public:
    TranslationBlockTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize(void);

    enum TbTracerOpcodes { Enable = 0, Disable = 1 };

    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

private:
    ExecutionTracer *m_tracer;
    ModuleExecutionDetector *m_detector;
    bool m_monitorModules;

    sigc::connection m_tbStartConnection;
    sigc::connection m_tbEndConnection;

    bool m_flushTbOnChange;

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                   TranslationBlock *tb, uint64_t endPc, bool staticTarget, uint64_t targetPc);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc,
                             bool staticTarget, uint64_t targetPc);

    bool getConcolicValue(S2EExecutionState *state, unsigned offset, uint64_t *value, unsigned size);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);
    void onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc);

    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);

public:
    void enableTracing();
    void disableTracing();
    bool tracingEnabled();

    void trace(S2EExecutionState *state, uint64_t pc, ExecTraceEntryType type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
