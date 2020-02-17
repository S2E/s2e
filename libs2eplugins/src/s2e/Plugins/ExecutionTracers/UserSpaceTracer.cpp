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

#include <TraceEntries.pb.h>
#include "UserSpaceTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(UserSpaceTracer, "Traces user-space processes", "", "ExecutionTracer", "OSMonitor");

void UserSpaceTracer::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_winmonitor = s2e()->getPlugin<WindowsMonitor>();

    if (m_winmonitor) {
        m_winmonitor->onAccessFault.connect(sigc::mem_fun(*this, &UserSpaceTracer::onAccessFault));
    }

    m_memoryTracer = s2e()->getPlugin<MemoryTracer>();
    m_tbTracer = s2e()->getPlugin<TranslationBlockTracer>();
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    m_tracing = false;

    ConfigFile *cfg = s2e()->getConfig();
    m_traceExecution = cfg->getBool(getConfigKey() + ".traceExecution", true);
    m_traceTranslation = cfg->getBool(getConfigKey() + ".traceTranslation", true);

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &UserSpaceTracer::onMonitorLoad));
}

void UserSpaceTracer::onMonitorLoad(S2EExecutionState *state) {
    if (m_traceTranslation) {
        if (m_monitor) {
            m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &UserSpaceTracer::onModuleLoad));
        }

        s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
            sigc::mem_fun(*this, &UserSpaceTracer::onTranslateBlockComplete));
    }
}

bool UserSpaceTracer::isTraced(uint64_t as) {
    foreach2 (it, p_pidsToTrace.begin(), p_pidsToTrace.end()) {
        if (*it == as) {
            return true;
        }
    }
    return false;
}

void UserSpaceTracer::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    // XXX: quick hack for Linux stuff.
    startTracing(state, module.AddressSpace);
}

void UserSpaceTracer::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode) {
    foreach2 (it, p_pidsToTrace.begin(), p_pidsToTrace.end()) {
        if (*it == pid) {
            getDebugStream(state) << "Not tracing " << hexval(pid) << " anymore\n";
            p_pidsToTrace.erase(it);
            return;
        }
    }
}

void UserSpaceTracer::onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault) {
    /**
     * Disconnect as soon as the kernel catches an invalid memory access.
     * This avoids cluttering the execution trace, which would only contain
     * items up to the faulty instruction.
     */
    if (isTraced(m_winmonitor->getCurrentProcessId(state))) {
        if ((uint32_t) AccessFault.StatusCode != 0xc0000005) {
            return;
        }

        getDebugStream(state) << "UserSpaceTracer: Caught MmAccessFault "
                              << " Address: " << hexval(AccessFault.Address)
                              << " AccessMode: " << hexval(AccessFault.AccessMode)
                              << " StatusCode: " << hexval(AccessFault.StatusCode)
                              << " PageDir: " << hexval(state->regs()->getPageDir()) << "\n";

        if (m_memoryTracer) {
            m_memoryTracer->enable(state, MemoryTracer::MEMORY, false);
        }
        m_privConnection.disconnect();
        m_tbConnection.disconnect();
        se_tb_safe_flush();
    }
}

void UserSpaceTracer::trace(S2EExecutionState *state, uint64_t startPc, uint64_t endPc, uint32_t type,
                            TranslationBlock *tb) {
    s2e_trace::PbTraceTranslationBlock item;

    assert(type == s2e_trace::TRACE_BLOCK);

    item.set_pc(startPc);
    item.set_last_pc(endPc);
    item.set_size(tb->size);
    item.set_tb_type(s2e_trace::PbTraceTbType(tb->se_tb_type));

    m_tracer->writeData(state, item, type);
}

void UserSpaceTracer::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc) {
    if ((tb->flags & HF_CPL_MASK) != 3) {
        return;
    }

    if (isTraced(getCurrentPid(state))) {
        trace(state, tb->pc, endPc, s2e_trace::TRACE_BLOCK, tb);
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
    if (isTraced(getCurrentPid(state))) {
        m_tbTracer->trace(state, pc, s2e_trace::TRACE_TB_START);
    }
}

void UserSpaceTracer::onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current) {
    if (current != 3 || !isTraced(getCurrentPid(state))) {
        if (m_memoryTracer) {
            m_memoryTracer->enable(state, MemoryTracer::MEMORY, false);
        }
    } else {
        if (m_memoryTracer) {
            m_memoryTracer->enable(state, MemoryTracer::MEMORY, true);
        }
    }
}

void UserSpaceTracer::startTracing(S2EExecutionState *state, uint64_t pid) {

    if ((int) pid == -1) {
        pid = getCurrentPid(state);
    }

    getDebugStream(state) << "Tracing pid " << hexval(pid) << "\n";
    if (isTraced(pid)) {
        getDebugStream(state) << "pid already traced\n";
        return;
    }

    p_pidsToTrace.push_back(pid);

    if (m_tracing || !m_traceExecution) {
        return;
    }

    if (m_memoryTracer) {
        getDebugStream() << "UserSpaceTracer: starting memory trace\n";
        m_memoryTracer->enable(state, MemoryTracer::MEMORY, true);
        m_privConnection = s2e()->getCorePlugin()->onPrivilegeChange.connect(
            sigc::mem_fun(*this, &UserSpaceTracer::onPrivilegeChange));
        m_tracing = true;
    }

    if (m_tbTracer) {
        getDebugStream() << "UserSpaceTracer: starting translation block trace\n";
        m_tbConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &UserSpaceTracer::onTranslateBlockStart));

        /* This ensures that next translation blocks will be instrumented */
        se_tb_safe_flush();
        m_tracing = true;
    }
}

} // namespace plugins
} // namespace s2e
