///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2019, Cyberhaven
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

#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <llvm/Support/CommandLine.h>

#include <inttypes.h>
#include <iomanip>

#include <TraceEntries.pb.h>

#include "MemoryTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryTracer, "Memory tracer plugin", "MemoryTracer", "ExecutionTracer");

namespace {

class MemoryTracerState : public PluginState {
private:
    bool m_activeTrace[MemoryTracer::MAX_ITEMS];

    // Users can selectively disable tracing by resetting items here
    bool m_traceOverride[MemoryTracer::MAX_ITEMS];

public:
    virtual MemoryTracerState *clone() const {
        return new MemoryTracerState(*this);
    }

    MemoryTracerState() {
        m_activeTrace[MemoryTracer::MEMORY] = false;
        m_activeTrace[MemoryTracer::TLB_MISSES] = false;
        m_activeTrace[MemoryTracer::PAGE_FAULT] = false;

        m_traceOverride[MemoryTracer::MEMORY] = false;
        m_traceOverride[MemoryTracer::TLB_MISSES] = false;
        m_traceOverride[MemoryTracer::PAGE_FAULT] = false;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new MemoryTracerState();
    }

    virtual ~MemoryTracerState() {
    }

    inline void activate(MemoryTracer::TraceType type, bool v) {
        m_activeTrace[type] = v;
    }

    inline bool enabled(MemoryTracer::TraceType type) const {
        return m_activeTrace[type] && m_traceOverride[type];
    }

    inline void override(MemoryTracer::TraceType type, bool v) {
        m_traceOverride[type] = v;
    }
};
} // namespace

MemoryTracer::MemoryTracer(S2E *s2e) : Plugin(s2e) {
}

void MemoryTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    // TODO: MemoryTracer will only work properly with ModuleExecutionDetector.
    m_tracker = ITracker::getTracker(s2e(), this);
    if (!m_tracker) {
        getWarningsStream() << "No filtering plugin specified. Tracing all memory accesses in the system.\n";
    }

    // Whether or not to include host addresses in the trace.
    // This is useful for debugging, bug yields larger traces
    m_traceHostAddresses = s2e()->getConfig()->getBool(getConfigKey() + ".traceHostAddresses");

    // Check that the current state is actually allowed to write to
    // the object state. Can be useful to debug the engine.
    m_debugObjectStates = s2e()->getConfig()->getBool(getConfigKey() + ".debugObjectStates");

    m_traceMemory = s2e()->getConfig()->getBool(getConfigKey() + ".traceMemory");
    m_tracePageFaults = s2e()->getConfig()->getBool(getConfigKey() + ".tracePageFaults");
    m_traceTlbMisses = s2e()->getConfig()->getBool(getConfigKey() + ".traceTlbMisses");

    getDebugStream() << "MonitorMemory: " << m_traceMemory << " PageFaults: " << m_tracePageFaults
                     << " TlbMisses: " << m_traceTlbMisses << '\n';

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &MemoryTracer::onTranslateBlockStart));

    s2e()->getCorePlugin()->onInitializationComplete.connect(
        sigc::mem_fun(*this, &MemoryTracer::onInitializationComplete));

    s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
        sigc::mem_fun(*this, &MemoryTracer::onAfterSymbolicDataMemoryAccess));

    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
        sigc::mem_fun(*this, &MemoryTracer::onConcreteDataMemoryAccess));

    s2e()->getCorePlugin()->onTlbMiss.connect(sigc::mem_fun(*this, &MemoryTracer::onTlbMiss));

    s2e()->getCorePlugin()->onPageFault.connect(sigc::mem_fun(*this, &MemoryTracer::onPageFault));
}

void MemoryTracer::onInitializationComplete(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    plgState->override(MemoryTracer::MEMORY, m_traceMemory);
    plgState->override(MemoryTracer::PAGE_FAULT, m_tracePageFaults);
    plgState->override(MemoryTracer::TLB_MISSES, m_traceTlbMisses);
}

void MemoryTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                         uint64_t pc) {
    bool traced = !m_tracker || m_tracker->isTracked(state);
    signal->connect(sigc::bind(sigc::mem_fun(*this, &MemoryTracer::onBlockStart), traced));
}

void MemoryTracer::onBlockStart(S2EExecutionState *state, uint64_t pc, bool traced_module) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    if (m_tracker && !m_tracker->isTracked(state)) {
        plgState->activate(MemoryTracer::MEMORY, false);
        plgState->activate(MemoryTracer::TLB_MISSES, false);
        plgState->activate(MemoryTracer::PAGE_FAULT, false);
        return;
    }

    plgState->activate(MemoryTracer::MEMORY, traced_module);
    plgState->activate(MemoryTracer::TLB_MISSES, traced_module);
    plgState->activate(MemoryTracer::PAGE_FAULT, traced_module);
}

void MemoryTracer::traceConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value,
                                                 uint8_t size, unsigned flags) {
    s2e_trace::PbTraceMemoryAccess item;
    item.set_pc(state->regs()->getPc());

    item.set_address(address);
    item.set_value(value);
    item.set_size(size);
    item.set_host_address(0);
    item.set_concrete_buffer(0);

    uint32_t traceFlags = 0;

    if (flags & MEM_TRACE_FLAG_WRITE) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_WRITE;
    }

    if (flags & MEM_TRACE_FLAG_IO) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_IO;
    }

    if (m_traceHostAddresses) {
        item.set_host_address(state->mem()->getHostAddress(address));
        item.set_concrete_buffer(0);

        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_HASHOSTADDR;
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_OBJECTSTATE;

        auto os = state->addressSpace.findObject(item.host_address() & SE_RAM_OBJECT_MASK);
        if (os) {
            item.set_concrete_buffer((uint64_t) os->getConcreteBuffer());
            if ((flags & MEM_TRACE_FLAG_WRITE) && m_debugObjectStates) {
                assert(state->addressSpace.isOwnedByUs(os));
            }
        }
    }

    item.set_flags(s2e_trace::PbTraceMemoryAccess::Flags(traceFlags));

    m_tracer->writeData(state, item, s2e_trace::TRACE_MEMORY);
}

void MemoryTracer::traceSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> &address,
                                                 klee::ref<klee::Expr> &hostAddress, klee::ref<klee::Expr> &value,
                                                 unsigned flags) {
    bool isAddrCste = isa<klee::ConstantExpr>(address);
    bool isValCste = isa<klee::ConstantExpr>(value);
    bool isHostAddrCste = isa<klee::ConstantExpr>(hostAddress);

    uint32_t traceFlags = 0;

    s2e_trace::PbTraceMemoryAccess item;
    item.set_pc(state->regs()->getPc());

    uint64_t concreteAddress = 0xdeadbeef;
    uint64_t concreteValue = 0xdeadbeef;

    klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(address));
    concreteAddress = ce->getZExtValue();

    ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(value));
    concreteValue = ce->getZExtValue();

    item.set_address(isAddrCste ? cast<klee::ConstantExpr>(address)->getZExtValue(64) : concreteAddress);
    item.set_value(isValCste ? cast<klee::ConstantExpr>(value)->getZExtValue(64) : concreteValue);
    item.set_size(klee::Expr::getMinBytesForWidth(value->getWidth()));

    if (flags & MEM_TRACE_FLAG_WRITE) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_WRITE;
    }

    if (flags & MEM_TRACE_FLAG_IO) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_IO;
    }

    item.set_host_address(isHostAddrCste ? cast<klee::ConstantExpr>(hostAddress)->getZExtValue(64) : 0xDEADBEEF);
    item.set_concrete_buffer(0);

    if (m_traceHostAddresses) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_HASHOSTADDR;
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_OBJECTSTATE;

        auto os = state->addressSpace.findObject(item.host_address() & SE_RAM_OBJECT_MASK);
        if (os) {
            item.set_concrete_buffer((uint64_t) os->getConcreteBuffer());
            if ((flags & MEM_TRACE_FLAG_WRITE) && m_debugObjectStates) {
                assert(state->addressSpace.isOwnedByUs(os));
            }
        }
    }

    if (!isAddrCste) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_SYMBADDR;
    }

    if (!isValCste) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_SYMBVAL;
    }

    if (!isHostAddrCste) {
        traceFlags |= s2e_trace::PbTraceMemoryAccess::EXECTRACE_MEM_SYMBHOSTADDR;
    }

    item.set_flags(s2e_trace::PbTraceMemoryAccess::Flags(traceFlags));

    m_tracer->writeData(state, item, s2e_trace::TRACE_MEMORY);
}

void MemoryTracer::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> address,
                                                   klee::ref<klee::Expr> hostAddress, klee::ref<klee::Expr> value,
                                                   unsigned flags) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    if (!plgState->enabled(MemoryTracer::MEMORY)) {
        return;
    }

    traceSymbolicDataMemoryAccess(state, address, hostAddress, value, flags);
}

void MemoryTracer::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t address, uint64_t value, uint8_t size,
                                              unsigned flags) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    if (!plgState->enabled(MemoryTracer::MEMORY)) {
        return;
    }

    traceConcreteDataMemoryAccess(state, address, value, size, flags);
}

void MemoryTracer::onTlbMiss(S2EExecutionState *state, uint64_t addr, bool is_write) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    if (!plgState->enabled(MemoryTracer::TLB_MISSES)) {
        return;
    }

    s2e_trace::PbTraceSimpleMemoryAccess item;

    item.set_pc(state->regs()->getPc());
    item.set_address(addr);
    item.set_is_write(is_write);

    std::string data;
    if (!item.AppendToString(&data)) {
        return;
    }

    m_tracer->writeData(state, data.c_str(), data.size(), s2e_trace::TRACE_TLBMISS);
}

void MemoryTracer::onPageFault(S2EExecutionState *state, uint64_t addr, bool is_write) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    if (!plgState->enabled(MemoryTracer::PAGE_FAULT)) {
        return;
    }

    s2e_trace::PbTraceSimpleMemoryAccess item;

    item.set_pc(state->regs()->getPc());
    item.set_address(addr);
    item.set_is_write(is_write);

    m_tracer->writeData(state, item, s2e_trace::TRACE_PAGEFAULT);
}

bool MemoryTracer::getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
    return false;
}

bool MemoryTracer::setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
    if (name == "trace") {
        DECLARE_PLUGINSTATE(MemoryTracerState, state);

        if (value == "1") {
            plgState->override(MemoryTracer::MEMORY, true);
        } else {
            plgState->override(MemoryTracer::MEMORY, false);
        }
        return true;
    }
    return false;
}

void MemoryTracer::enable(S2EExecutionState *state, TraceType type, bool v) {
    DECLARE_PLUGINSTATE(MemoryTracerState, state);
    plgState->override(type, v);
}
} // namespace plugins
} // namespace s2e
