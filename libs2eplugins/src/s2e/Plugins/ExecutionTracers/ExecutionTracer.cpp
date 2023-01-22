///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <TraceEntries.pb.h>

#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExecutionTracer, "ExecutionTracer plugin", "", );

void ExecutionTracer::initialize() {
    createNewTraceFile(false);

    // Execution tracers must have the highest signal priority.
    // That's because others plugins might kill states. If these other plugins have
    // a higher priority, the tracer's handlers won't be calle and the execution
    // trace won't have the corresponding record. This would essentially render
    // the trace corrupted. So we trust that other plugins assign themselves
    // a lower priority if they can potentially kill states in their signal handlers.
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &ExecutionTracer::onFork),
                                                fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &ExecutionTracer::onTimer),
                                            fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onProcessFork.connect(sigc::mem_fun(*this, &ExecutionTracer::onProcessFork),
                                                  fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onStateGuidAssignment.connect(sigc::mem_fun(*this, &ExecutionTracer::onStateGuidAssignment),
                                                          fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &ExecutionTracer::onEngineShutdown));

    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &ExecutionTracer::onStateKill));

    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    if (m_monitor) {
        m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &ExecutionTracer::onMonitorLoad));
    }
}

ExecutionTracer::~ExecutionTracer() {
    onEngineShutdown();
}

void ExecutionTracer::onStateKill(S2EExecutionState *state) {
    flush();
}

void ExecutionTracer::onEngineShutdown() {
    if (m_logFile) {
        fclose(m_logFile);
        m_logFile = nullptr;
    }
}

void ExecutionTracer::createNewTraceFile(bool append) {

    if (append) {
        assert(m_fileName.size() > 0);
        m_logFile = fopen(m_fileName.c_str(), "a");
    } else {
        m_fileName = s2e()->getOutputFilename("ExecutionTracer.dat");
        m_logFile = fopen(m_fileName.c_str(), "wb");
    }

    if (!m_logFile) {
        getWarningsStream() << "Could not create ExecutionTracer.dat" << '\n';
        exit(-1);
    }
    m_currentIndex = 0;
}

void ExecutionTracer::onTimer() {
    if (m_logFile) {
        fflush(m_logFile);
    }
}

bool ExecutionTracer::appendToTraceFile(const s2e_trace::PbTraceItemHeader &header, const void *data, unsigned size) {
    std::string headerStr;
    if (!header.AppendToString(&headerStr)) {
        return false;
    }

    // Start each trace entry (header + item) with a magic number
    // in order to easily spot corruptions during trace processing.
    uint32_t prefix[] = {0xdeaddead, (uint32_t) headerStr.size()};

    if (fwrite(&prefix[0], sizeof(prefix), 1, m_logFile) != 1) {
        return false;
    }

    if (fwrite(headerStr.c_str(), headerStr.size(), 1, m_logFile) != 1) {
        return false;
    }

    if (fwrite(&size, sizeof(size), 1, m_logFile) != 1) {
        return false;
    }

    if (size) {
        if (fwrite(data, size, 1, m_logFile) != 1) {
            return false;
        }
    }

    return true;
}

uint32_t ExecutionTracer::writeData(S2EExecutionState *state, const void *data, unsigned size, uint32_t type) {
    assert(m_logFile);

    s2e_trace::PbTraceItemHeader header;

    header.set_address_space(state->regs()->getPageDir());
    header.set_pc(state->regs()->getPc());

    if (m_monitor && m_monitor->initialized()) {
        header.set_pid(m_monitor->getPid(state));
        header.set_tid(m_monitor->getTid(state));
    } else {
        header.set_pid(0);
        header.set_tid(0);
    }

    return writeData(state, header, data, size, type);
}

uint32_t ExecutionTracer::writeData(S2EExecutionState *state, s2e_trace::PbTraceItemHeader &header, const void *data,
                                    unsigned size, uint32_t type /* s2e_trace::PbTraceItemHeaderType */) {
    assert(m_logFile);

    // We must take the guid instead of the id, because duplicate ids
    // across multiple traces will confuse the execution trace reader.
    header.set_state_id(state->getGuid());
    auto now = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    header.set_timestamp(us);
    header.set_type(s2e_trace::PbTraceItemHeaderType(type));

    if (!appendToTraceFile(header, data, size)) {
        getWarningsStream(state) << "Could not write to trace file\n";
        exit(-1);
    }

    return ++m_currentIndex;
}

void ExecutionTracer::flush() {
    if (m_logFile) {
        fflush(m_logFile);
    }
}

void ExecutionTracer::onProcessFork(bool preFork, bool isChild, unsigned parentProcId) {
    if (preFork) {
        fclose(m_logFile);
        m_logFile = nullptr;
    } else {
        if (isChild) {
            createNewTraceFile(false);
        } else {
            createNewTraceFile(true);
        }
    }
}

///
/// \brief Handle state guid reassignment by creating a fake fork
///
/// When the load blancer forks a new instance of S2E, that child instance
/// may contain states that are also present in the parent. This fork must be
/// reflected in the trace so that trace processing tools can still
/// reconstruct a proper execution tree. For this, the execution tracer
/// creates a fork entry that works in the same way as if the state was
/// forked normally as part of normal symbolic execution. This fork entry
/// is created in the parent instance's execution trace.
///
/// \param state the state that was split.
///
void ExecutionTracer::onStateGuidAssignment(S2EExecutionState *state, uint64_t newGuid) {
    s2e_trace::PbTraceItemFork item;
    item.add_children(state->getGuid());
    item.add_children(newGuid);
    writeData(state, item, s2e_trace::PbTraceItemHeaderType::TRACE_FORK);
}

void ExecutionTracer::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                             const std::vector<klee::ref<klee::Expr>> &newConditions) {
    assert(newStates.size() > 0);

    s2e_trace::PbTraceItemFork item;

    for (unsigned i = 0; i < newStates.size(); i++) {
        item.add_children(newStates[i]->getGuid());
    }

    writeData(state, item, s2e_trace::PbTraceItemHeaderType::TRACE_FORK);
}

void ExecutionTracer::onMonitorLoad(S2EExecutionState *state) {
    s2e_trace::PbTraceOsInfo item;
    item.set_kernel_start(m_monitor->getKernelStart());
    writeData(state, item, s2e_trace::PbTraceItemHeaderType::TRACE_OSINFO);
}

} // namespace plugins
} // namespace s2e

extern "C" {

/** Can be called from GDB to flush the trace from the debugger */
void execution_tracer_flush(void);
void execution_tracer_flush(void) {
    s2e::plugins::ExecutionTracer *tracer;

    tracer = g_s2e->getPlugin<s2e::plugins::ExecutionTracer>();
    if (!tracer) {
        return;
    }

    tracer->flush();
}
}
