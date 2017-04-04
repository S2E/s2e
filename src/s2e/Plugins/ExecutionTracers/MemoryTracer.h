///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MEMTRACER_H
#define S2E_PLUGINS_MEMTRACER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <string>

#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

/** Handler required for KLEE interpreter */
class MemoryTracer : public Plugin {
    S2E_PLUGIN

private:
public:
    MemoryTracer(S2E *s2e);

    void initialize();

    enum MemoryTracerOpcodes { Enable = 0, Disable = 1 };

private:
    bool m_monitorPageFaults;
    bool m_monitorTlbMisses;
    bool m_monitorMemory;

    bool m_monitorModules;
    bool m_monitorStack;

    bool m_traceHostAddresses;
    bool m_debugObjectStates;

    uint64_t m_catchAbove;
    uint64_t m_catchBelow;

    uint64_t m_timeTrigger;
    uint64_t m_elapsedTics;
    sigc::connection m_timerConnection;

    sigc::connection m_concreteMemoryMonitor;
    sigc::connection m_symbolicMemoryMonitor;

    sigc::connection m_pageFaultsMonitor;
    sigc::connection m_tlbMissesMonitor;

    ExecutionTracer *m_tracer;
    ModuleExecutionDetector *m_execDetector;

    void onTlbMiss(S2EExecutionState *state, uint64_t addr, bool is_write);
    void onPageFault(S2EExecutionState *state, uint64_t addr, bool is_write);

    void onTimer();

    void enableTracing();
    void disableTracing();
    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);

    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                         klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                         unsigned flags);

    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr, uint64_t value, uint8_t size,
                                    unsigned flags);

    void onModuleTransition(S2EExecutionState *state, const ModuleDescriptor *prevModule,
                            const ModuleDescriptor *nextModule);

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    bool forceDisconnect(S2EExecutionState *state);

    bool decideTracing(S2EExecutionState *state);

public:
    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

    // May be called directly by other plugins
    void traceSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> &address,
                                       klee::ref<klee::Expr> &hostAddress, klee::ref<klee::Expr> &value,
                                       unsigned flags);

    void traceConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                       unsigned flags);

    void connectMemoryTracing();
    void disconnectMemoryTracing();
    bool tracingEnabled();
};
}
}

#endif
