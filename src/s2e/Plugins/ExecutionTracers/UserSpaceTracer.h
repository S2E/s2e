///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_UserSpaceTracer_H
#define S2E_PLUGINS_UserSpaceTracer_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/ExecutionTracers/MemoryTracer.h>
#include <s2e/Plugins/ExecutionTracers/TranslationBlockTracer.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {

class UserSpaceTracer : public Plugin {
    S2E_PLUGIN
public:
    UserSpaceTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void startTracing(S2EExecutionState *state, uint64_t pid = -1);

private:
    OSMonitor *m_monitor;
    WindowsMonitor *m_winmonitor;
    MemoryTracer *m_memoryTracer;
    TranslationBlockTracer *m_tbTracer;
    ExecutionTracer *m_tracer;

    // XXX: must be per-state eventually
    llvm::SmallVector<uint64_t, 4> p_pidsToTrace;
    bool m_tracing;

    sigc::connection m_privConnection;
    sigc::connection m_tbConnection;

    bool m_traceExecution;
    bool m_traceTranslation;

    void onMonitorLoad(S2EExecutionState *state);
    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    inline uint64_t getCurrentPid(S2EExecutionState *state) {
        if (m_winmonitor) {
            return m_winmonitor->getCurrentProcessId(state);
        }
        return state->getPageDir();
    }

    bool isTraced(uint64_t as);

    void trace(S2EExecutionState *state, uint64_t startPc, uint64_t endPc, ExecTraceEntryType type,
               TranslationBlock *tb);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc);

    void onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    void onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_UserSpaceTracer_H
