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
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <string>

#include "ExecutionTracer.h"
#include "ModuleTracing.h"

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

    enum TraceType { MEMORY = 0, TLB_MISSES = 1, PAGE_FAULT = 2, MAX_ITEMS = 3 };

private:
    bool m_tracePageFaults;
    bool m_traceTlbMisses;
    bool m_traceMemory;

    bool m_traceHostAddresses;
    bool m_debugObjectStates;

    ExecutionTracer *m_tracer;
    ProcessExecutionDetector *m_detector;

    ModuleTracing m_modules;

    void onTlbMiss(S2EExecutionState *state, uint64_t addr, bool is_write);
    void onPageFault(S2EExecutionState *state, uint64_t addr, bool is_write);

    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                         klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                         unsigned flags);

    void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t vaddr, uint64_t value, uint8_t size,
                                    unsigned flags);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onBlockStart(S2EExecutionState *state, uint64_t pc, bool traced_module);
    void onInitializationComplete(S2EExecutionState *state);

public:
    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

    // May be called directly by other plugins
    void traceSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> &address,
                                       klee::ref<klee::Expr> &hostAddress, klee::ref<klee::Expr> &value,
                                       unsigned flags);

    void traceConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                       unsigned flags);

    void enable(S2EExecutionState *state, TraceType type, bool v);
};
} // namespace plugins
} // namespace s2e

#endif
