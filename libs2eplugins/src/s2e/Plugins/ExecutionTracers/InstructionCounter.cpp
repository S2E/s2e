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
#include <s2e/Plugins/OSMonitors/Support/PidTid.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include "InstructionCounter.h"

#include <TraceEntries.pb.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionCounter, "Instruction counter plugin", "InstructionCounter", "ExecutionTracer",
                  "ProcessExecutionDetector", "ModuleMap", "OSMonitor");

namespace {
class InstructionCounterState : public PluginState {
public:
    using Counts = std::unordered_map<PidTid, uint64_t /* count */>;

private:
    bool m_enabled = false;

    uint64_t m_count = 0;
    PidTid m_current = PidTid(-1, -1);
    Counts m_counts;

public:
    InstructionCounterState(S2EExecutionState *s, Plugin *p){

    };

    virtual ~InstructionCounterState(){};
    virtual PluginState *clone() const {
        return new InstructionCounterState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new InstructionCounterState(s, p);
    }

    inline void updatePidTid(uint64_t pid, uint64_t tid) {
        auto pt = PidTid(pid, tid);
        if (m_current != pt) {
            m_counts[m_current] = m_count;
            m_count = m_counts[pt];
            m_current = pt;
        }
    }

    inline void flush() {
        m_counts[m_current] = m_count;
        m_count = 0;
        m_current = PidTid(-1, -1);
    }

    inline void inc() {
        m_count++;
    }

    inline void set(uint64_t v) {
        m_count = v;
    }

    inline Counts &get() {
        return m_counts;
    }

    inline uint64_t getCount() const {
        return m_count;
    }

    inline void enable(bool v) {
        m_enabled = v;
    }

    inline bool enabled() const {
        return m_enabled;
    }
};
} // namespace

void InstructionCounter::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_tracker = ITracker::getTracker(s2e(), this);
    if (m_tracker) {
        m_tracker->onConfigChange.connect(sigc::mem_fun(*this, &InstructionCounter::onConfigChange));
    } else {
        getWarningsStream() << "No filtering plugin specified. Counting all instructions in the system.\n";
    }

    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &InstructionCounter::onStateKill));

    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &InstructionCounter::onProcessUnload));
    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &InstructionCounter::onThreadExit));
    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &InstructionCounter::onMonitorLoad));
    m_monitor->onProcessOrThreadSwitch.connect(sigc::mem_fun(*this, &InstructionCounter::onProcessOrThreadSwitch));
}

void InstructionCounter::onConfigChange(S2EExecutionState *state) {
    // The plugin will need to re-instrument blocks in case the tracker's
    // configuration changes.
    se_tb_safe_flush();
}

void InstructionCounter::onMonitorLoad(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &InstructionCounter::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &InstructionCounter::onTranslateInstructionStart));

    // Make sure we don't miss any TBs.
    se_tb_safe_flush();
}

void InstructionCounter::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                               uint64_t pc) {
    if (m_tracker && !m_tracker->isTrackingConfigured(state)) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &InstructionCounter::onTbExecuteStart));
}

void InstructionCounter::onTbExecuteStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    if (m_tracker && !m_tracker->isTracked(state)) {
        plgState->enable(false);
        return;
    }
    plgState->enable(true);
}

void InstructionCounter::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc) {
    // Connect a function that will increment the number of executed instructions.
    signal->connect(sigc::mem_fun(*this, &InstructionCounter::onInstruction));
}

void InstructionCounter::onInstruction(S2EExecutionState *state, uint64_t pc) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    if (plgState->enabled()) {
        plgState->inc();
    }
}

void InstructionCounter::writeData(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t count) {
    if (count == 0) {
        return;
    }

    if (pid == -1 && tid == -1) {
        return;
    }

    s2e_trace::PbTraceItemHeader header;

    header.set_address_space(-1);
    header.set_pc(-1);

    header.set_pid(pid);
    header.set_tid(tid);

    s2e_trace::PbTraceInstructionCount item;
    item.set_count(count);
    m_tracer->writeData(state, header, item, s2e_trace::TRACE_ICOUNT);
}

void InstructionCounter::onStateKill(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    plgState->flush();

    for (auto kv : plgState->get()) {
        auto pid = kv.first.first;
        auto tid = kv.first.second;
        writeData(state, pid, tid, kv.second);
    }
}

void InstructionCounter::onProcessOrThreadSwitch(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    plgState->updatePidTid(m_monitor->getPid(state), m_monitor->getTid(state));
}

void InstructionCounter::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    plgState->flush();

    auto &counts = plgState->get();
    for (auto kv : counts) {
        auto pid = kv.first.first;
        auto tid = kv.first.second;

        if (pid == thread.Pid && tid == thread.Tid) {
            writeData(state, pid, tid, kv.second);
            counts.erase(std::make_pair(pid, tid));
            break;
        }
    }
}

void InstructionCounter::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t ppid,
                                         uint64_t returnCode) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);
    plgState->flush();

    std::vector<PidTid> toErase;

    auto &counts = plgState->get();
    for (auto kv : counts) {
        auto pid = kv.first.first;
        auto tid = kv.first.second;

        if (pid == ppid) {
            writeData(state, pid, tid, kv.second);
            toErase.push_back(std::make_pair(pid, tid));
        }
    }

    for (auto &pt : toErase) {
        counts.erase(pt);
    }
}

void InstructionCounter::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                uint64_t guestDataSize) {
    DECLARE_PLUGINSTATE(InstructionCounterState, state);

    S2E_ICOUNT_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_ICOUNT_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case ICOUNT_RESET:
            plgState->set(0);
            break;

        case ICOUNT_GET:
            command.Count = plgState->getCount();
            break;
    }

    if (!state->mem()->write(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not write transmitted data\n";
        exit(-1);
    }
}

} // namespace plugins
} // namespace s2e
