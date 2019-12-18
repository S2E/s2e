///
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FunctionMonitor_H
#define S2E_PLUGINS_FunctionMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

namespace s2e {

class S2EExecutionState;
struct ThreadDescriptor;

namespace plugins {

class ModuleMap;
class OSMonitor;
class ProcessExecutionDetector;

///
/// \brief The FunctionMonitor class tracks call/return instruction pairs.
///
/// Clients use the onCall signal to be notified of call instructions and
/// optionally of return instructions in case they choose to register the corresponding
/// return signal. Call/return signals are paired and work for recursive functions too.
/// Note that compilers may introduce various optimizations (e.g., tail calls), which
/// may interfere with return signals.
///
/// This plugin only tracks modules in processes registered with ProcessExecutionDetector.
///
class FunctionMonitor : public Plugin {
    S2E_PLUGIN

public:
    FunctionMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    // Source and/or dest module can be null
    typedef sigc::signal<void, S2EExecutionState * /* state after return is completed */,
                         const ModuleDescriptorConstPtr & /* module at return site */,
                         const ModuleDescriptorConstPtr & /* module to which execution returns (ret addr) */,
                         uint64_t /* return site */
                         >
        ReturnSignal;

    typedef std::shared_ptr<ReturnSignal> ReturnSignalPtr;

    ///
    /// \brief onCall
    ///
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptorConstPtr & /* caller module */,
                 const ModuleDescriptorConstPtr & /* callee module */, uint64_t /* caller PC */,
                 uint64_t /* callee PC */, const ReturnSignalPtr &>
        onCall;

private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_processDetector;
    ModuleMap *m_map;

    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);
    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onFunctionCall(S2EExecutionState *state, uint64_t pc);
    void onFunctionReturn(S2EExecutionState *state, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FunctionMonitor_H
