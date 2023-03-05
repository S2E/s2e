///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/ExecutionTracers/MemoryTracer.h>
#include <s2e/Plugins/ExecutionTracers/TranslationBlockTracer.h>
#include <s2e/Plugins/OSMonitors/Support/PidTid.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include <TraceEntries.pb.h>
#include "UserSpaceTracer.h"

namespace s2e {
namespace plugins {

// TODO: add support for Linux
S2E_DEFINE_PLUGIN(UserSpaceTracer, "Trace execution of user-space Windows processes", "", "ExecutionTracer",
                  "WindowsMonitor");

class UserSpaceTracerState : public PluginState {
public:
    struct TraceInfo {
        // How many blocks are left to trace for the thread.
        uint64_t itemsCountLeft;
    };

    using TraceInfoPtr = std::shared_ptr<TraceInfo>;

    using Pid = uint64_t;
    using PidTids = std::unordered_map<PidTid, TraceInfoPtr>;
    using Pids = llvm::DenseSet<Pid>;

private:
    PidTid m_current;
    TraceInfoPtr m_currentInfo;
    Pids m_pids;
    PidTids m_tids;

    bool m_trace = false;

    void updateTracing() {
        bool trace = false;
        m_currentInfo = nullptr;

        trace |= m_pids.find(m_current.first) != m_pids.end();
        auto it = m_tids.find(m_current);
        if (it != m_tids.end()) {
            m_currentInfo = (*it).second;
            if (m_currentInfo->itemsCountLeft > 0) {
                --m_currentInfo->itemsCountLeft;
                trace = true;
            }
        }
        m_trace = trace;
    }

public:
    inline PidTid getPidTid() const {
        return m_current;
    }

    void setPidTid(uint64_t pid, uint64_t tid) {
        m_current = PidTid(pid, tid);
        updateTracing();
    }

    void tracePid(uint64_t pid, bool trace) {
        if (trace) {
            m_pids.insert(pid);
        } else {
            m_pids.erase(pid);
        }
        updateTracing();
    }

    void traceTid(uint64_t pid, uint64_t tid, bool trace, uint64_t maxTraceItems = -1) {
        auto p = PidTid(pid, tid);
        if (trace) {
            if (maxTraceItems > 0) {
                auto info = std::make_shared<TraceInfo>();
                info->itemsCountLeft = maxTraceItems;
                m_tids[p] = info;
            }
        } else {
            m_tids.erase(p);
        }
        updateTracing();
    }

    inline bool traced(bool decrement = false) {
        if (!m_trace) {
            return false;
        }

        if (decrement && m_currentInfo) {
            if (m_currentInfo->itemsCountLeft > 0) {
                --m_currentInfo->itemsCountLeft;
                return true;
            } else {
                traceTid(m_current.first, m_current.second, false);
                return false;
            }
        }

        return true;
    }

    inline bool hasTracedProcesses() const {
        return !m_tids.empty() || !m_pids.empty();
    }

    void unloadProcess(uint64_t pid) {
        m_pids.erase(pid);
        PidTids toErase;
        for (auto pt : m_tids) {
            if (pt.first.first == pid) {
                toErase.insert(pt);
            }
        }
        for (auto pt : toErase) {
            m_tids.erase(pt.first);
        }

        updateTracing();
    }

    void unloadThread(uint64_t pid, uint64_t tid) {
        m_tids.erase(PidTid(pid, tid));
        updateTracing();
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new UserSpaceTracerState();
    }

    virtual ~UserSpaceTracerState() {
        // Destroy any object if needed
    }

    virtual UserSpaceTracerState *clone() const {
        return new UserSpaceTracerState(*this);
    }
};

void UserSpaceTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_memoryTracer = s2e()->getPlugin<MemoryTracer>();
    m_monitor = s2e()->getPlugin<WindowsMonitor>();

    ConfigFile *cfg = s2e()->getConfig();
    auto procs = cfg->getStringList(getConfigKey() + ".processNames");
    m_processNames.insert(procs.begin(), procs.end());
    if (m_processNames.empty()) {
        getWarningsStream() << "No process names specified. Tracing will not work unless other plugins enable it.\n";
    }

    m_traceExecution = cfg->getBool(getConfigKey() + ".traceExecution", false);
    m_traceTranslation = cfg->getBool(getConfigKey() + ".traceTranslation", false);
    m_traceMemory = cfg->getBool(getConfigKey() + ".traceMemory", false);

    if (m_traceMemory && !m_memoryTracer) {
        getWarningsStream() << "Tracing memory requires enabling the MemoryTracer plugin\n";
        exit(-1);
    }

    if (!m_traceExecution && !m_traceTranslation && !m_traceMemory) {
        getWarningsStream() << "All tracing options disabled\n";
    }

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &UserSpaceTracer::onMonitorLoad));
}

void UserSpaceTracer::onMonitorLoad(S2EExecutionState *state) {
    m_monitor->onProcessOrThreadSwitch.connect(sigc::mem_fun(*this, &UserSpaceTracer::onProcessOrThreadSwitch));
    m_monitor->onAccessFault.connect(sigc::mem_fun(*this, &UserSpaceTracer::onAccessFault));

    m_monitor->onProcessLoad.connect(sigc::mem_fun(*this, &UserSpaceTracer::onProcessLoad));
    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &UserSpaceTracer::onThreadExit));
    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &UserSpaceTracer::onStateSwitch));
}

// To minimize overhead, insert instrumentation only when there is at least one process
// that needs to be traced.
void UserSpaceTracer::updateInstrumentation(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);

    if (plgState->hasTracedProcesses()) {
        if (m_traceTranslation) {
            m_tbComplete = s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
                sigc::mem_fun(*this, &UserSpaceTracer::onTranslateBlockComplete));
        }

        if (m_traceExecution) {
            m_tbStart = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                sigc::mem_fun(*this, &UserSpaceTracer::onTranslateBlockStart));

            // This ensures that next translation blocks will be instrumented
            se_tb_safe_flush();
        }
    } else {
        m_tbComplete.disconnect();
        m_tbStart.disconnect();
        se_tb_safe_flush();
    }
}

void UserSpaceTracer::onStateSwitch(S2EExecutionState *current, S2EExecutionState *next) {
    if (!next) {
        return;
    }

    updateInstrumentation(next);
}

void UserSpaceTracer::onProcessOrThreadSwitch(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);

    auto pid = m_monitor->getCurrentProcessId(state);
    auto tid = m_monitor->getCurrentThreadId(state);
    plgState->setPidTid(pid, tid);
}

void UserSpaceTracer::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                    const std::string &imageName) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    if (m_processNames.find(imageName) != m_processNames.end()) {
        plgState->tracePid(pid, true);
    }
}

void UserSpaceTracer::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->unloadProcess(pid);
}

void UserSpaceTracer::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->unloadThread(thread.Pid, thread.Tid);
}

// TODO: make this optional
void UserSpaceTracer::onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);

    // Disconnect as soon as the kernel catches an invalid memory access.
    // This avoids cluttering the execution trace, which would only contain
    // items up to the faulty instruction.
    if (plgState->traced()) {
        if ((uint32_t) AccessFault.StatusCode != 0xc0000005) {
            return;
        }

        getDebugStream(state) << "UserSpaceTracer: Caught MmAccessFault "
                              << " Address: " << hexval(AccessFault.Address)
                              << " AccessMode: " << hexval(AccessFault.AccessMode)
                              << " StatusCode: " << hexval(AccessFault.StatusCode)
                              << " PageDir: " << hexval(state->regs()->getPageDir()) << "\n";

        auto p = plgState->getPidTid();
        plgState->traceTid(p.first, p.second, false);
    }
}

void UserSpaceTracer::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc) {
    if ((tb->flags & HF_CPL_MASK) != 3) {
        return;
    }

    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    if (plgState->traced()) {
        TranslationBlockTracer::trace(state, m_tracer, state->getTb(), s2e_trace::TRACE_BLOCK);
    }
}

void UserSpaceTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                            uint64_t pc) {
    if ((tb->flags & HF_CPL_MASK) != 3) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &UserSpaceTracer::onExecuteBlockStart));
}

void UserSpaceTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    if (plgState->traced(true)) {
        TranslationBlockTracer::trace(state, m_tracer, state->getTb(), s2e_trace::TRACE_TB_START);
    }
}

void UserSpaceTracer::onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    bool trace = current == 3 && plgState->traced();
    if (m_traceMemory) {
        m_memoryTracer->enable(state, MemoryTracer::MEMORY, trace);
    }
}

void UserSpaceTracer::startTracing(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->tracePid(pid, true);
    updateInstrumentation(state);
}

void UserSpaceTracer::startTracing(S2EExecutionState *state, uint64_t pid, uint64_t tid, uint64_t maxTraceItems) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->traceTid(pid, tid, true, maxTraceItems);
    updateInstrumentation(state);
}

void UserSpaceTracer::stopTracing(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->tracePid(pid, false);
    updateInstrumentation(state);
}

void UserSpaceTracer::stopTracing(S2EExecutionState *state, uint64_t pid, uint64_t tid) {
    DECLARE_PLUGINSTATE(UserSpaceTracerState, state);
    plgState->traceTid(pid, tid, false);
    updateInstrumentation(state);
}

} // namespace plugins
} // namespace s2e
