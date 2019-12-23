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

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

class TranslationBlockTracer : public Plugin {
    S2E_PLUGIN
public:
    enum TraceType { TB_START = 0, TB_END = 1, MAX_ITEMS = 2 };

    TranslationBlockTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize(void);

    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

private:
    ExecutionTracer *m_tracer;
    ProcessExecutionDetector *m_detector;
    ModuleMap *m_modules;

    bool m_traceTbStart;
    bool m_traceTbEnd;

    std::unordered_set<std::string> m_enabledModules;

    bool isModuleTraced(S2EExecutionState *state, uint64_t pc);

    void onInitializationComplete(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);

    void onBlockStartEnd(S2EExecutionState *state, uint64_t pc, bool isStart);
    void onBlockStart(S2EExecutionState *state, uint64_t pc);
    void onBlockEnd(S2EExecutionState *state, uint64_t pc);

public:
    void enableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type);
    void disableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type);
    bool tracingEnabled(S2EExecutionState *state, TranslationBlockTracer::TraceType type);

    void trace(S2EExecutionState *state, uint64_t pc, uint32_t type /* s2e_trace::PbTraceItemHeaderType */);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_TBTRACER_H
