///
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FunctionMonitor2_H
#define S2E_PLUGINS_FunctionMonitor2_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class ModuleMap;
class OSMonitor;
class ProcessExecutionDetector;

class FunctionMonitor2 : public Plugin {
    S2E_PLUGIN

public:
    FunctionMonitor2(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor * /* caller module */,
                 const ModuleDescriptor * /* callee module */, uint64_t /* caller PC */, uint64_t /* callee PC */>
        onCall;

private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_processDetector;
    ModuleMap *m_map;

    void onFunctionCall(S2EExecutionState *state, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FunctionMonitor2_H
