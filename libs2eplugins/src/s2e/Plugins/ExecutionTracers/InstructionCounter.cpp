///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include "InstructionCounter.h"

#include <TraceEntries.pb.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionCounter, "Instruction counter plugin", "InstructionCounter", "ExecutionTracer",
                  "ProcessExecutionDetector", "ModuleMap");

namespace {
class InstructionCounterState : public PluginState {
private:
    uint64_t m_count;
    bool m_enabled;
    void *m_cachedTb;

public:
    InstructionCounterState() {
        m_count = 0;
        m_enabled = false;
    }

    InstructionCounterState(S2EExecutionState *s, Plugin *p){};
    virtual ~InstructionCounterState(){};
    virtual PluginState *clone() const {
        return new InstructionCounterState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new InstructionCounterState(s, p);
    }

    inline void inc() {
        m_count++;
    }

    inline uint64_t get() const {
        return m_count;
    }

    inline void enable(bool v) {
        m_enabled = v;
    }

    inline bool enabled() const {
        return m_enabled;
    }

    inline void *getCachedTb() const {
        return m_cachedTb;
    }

    inline void setCachedTb(void *tb) {
        m_cachedTb = tb;
    }
};
} // namespace

void InstructionCounter::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_modules.initialize(s2e(), getConfigKey());

    s2e()->getCorePlugin()->onInitializationComplete.connect(
        sigc::mem_fun(*this, &InstructionCounter::onInitializationComplete));
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &InstructionCounter::onTranslateBlockStart));
    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &InstructionCounter::onStateKill));
}

void InstructionCounter::onInitializationComplete(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    plgState->enable(true);
}

void InstructionCounter::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                               uint64_t pc) {
    if (!m_modules.isModuleTraced(state, pc)) {
        m_tbConnection.disconnect();
        return;
    }

    if (!m_tbConnection.connected()) {
        CorePlugin *plg = s2e()->getCorePlugin();
        m_tbConnection = plg->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionCounter::onTranslateInstructionStart));
    }
}

void InstructionCounter::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc) {
    // Connect a function that will increment the number of executed instructions.
    signal->connect(sigc::mem_fun(*this, &InstructionCounter::onInstruction));
}

void InstructionCounter::onInstruction(S2EExecutionState *state, uint64_t pc) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    if (!plgState->enabled()) {
        return;
    }

    // This is an optimization to avoid expensive module lookups
    if (plgState->getCachedTb() == state->getTb()) {
        plgState->inc();
        return;
    }

    if (m_modules.isModuleTraced(state, pc)) {
        plgState->inc();
        plgState->setCachedTb(state->getTb());
    }
}

void InstructionCounter::onStateKill(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    // Flush the counter
    s2e_trace::PbTraceInstructionCount item;
    item.set_count(plgState->get());
    m_tracer->writeData(state, item, s2e_trace::TRACE_ICOUNT);
}

} // namespace plugins
} // namespace s2e
