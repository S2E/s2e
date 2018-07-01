///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ExecutionTracer.h"

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <llvm/Support/TimeValue.h>

#include <iostream>

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

    m_useCircularBuffer = s2e()->getConfig()->getBool(getConfigKey() + ".useCircularBuffer");

    if (m_useCircularBuffer) {
        m_circularBuffer.set_capacity(10000000);
    }

    m_Monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    if (m_Monitor) {
        m_Monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &ExecutionTracer::onMonitorLoad));
    }
}

ExecutionTracer::~ExecutionTracer() {
    if (m_LogFile) {
        fclose(m_LogFile);
    }
}

void ExecutionTracer::createNewTraceFile(bool append) {

    if (append) {
        assert(m_fileName.size() > 0);
        m_LogFile = fopen(m_fileName.c_str(), "a");
    } else {
        m_fileName = s2e()->getOutputFilename("ExecutionTracer.dat");
        m_LogFile = fopen(m_fileName.c_str(), "wb");
    }

    if (!m_LogFile) {
        getWarningsStream() << "Could not create ExecutionTracer.dat" << '\n';
        exit(-1);
    }
    m_CurrentIndex = 0;
}

void ExecutionTracer::onTimer() {
    if (m_LogFile) {
        fflush(m_LogFile);
    }
}

void ExecutionTracer::appendToCircularBuffer(const ExecutionTraceItemHeader *header, const void *data, unsigned size) {
    if (m_circularBuffer.full()) {
        const ExecutionTraceAllItems &item = *m_circularBuffer.begin();
        const ExecutionTraceItemHeader &h = item.header;

        /* Don't record heavy-weight stuff */
        bool notTraceable = (h.type == TRACE_MEMORY || h.type == TRACE_TB_START || h.type == TRACE_TB_END);
        if (!notTraceable) {
            appendToTraceFile(&item.header, &item.u, item.header.size);
        }
    }

    ExecutionTraceAllItems item;
    if (sizeof(*header) + size <= sizeof(item)) {
        item.header = *header;
        memcpy(&item.u, data, size);
        m_circularBuffer.push_back(item);
    }
}

bool ExecutionTracer::appendToTraceFile(const ExecutionTraceItemHeader *header, const void *data, unsigned size) {
    if (fwrite(header, sizeof(*header), 1, m_LogFile) != 1) {
        return false;
    }

    if (size) {
        if (fwrite(data, size, 1, m_LogFile) != 1) {
            // at this point the log is corrupted.
            assert(false);
        }
    }

    return true;
}

uint32_t ExecutionTracer::writeData(S2EExecutionState *state, void *data, unsigned size, ExecTraceEntryType type) {
    ExecutionTraceItemHeader item;

    assert(m_LogFile);

    item.timeStamp = llvm::sys::TimeValue::now().usec();
    item.size = size;
    item.type = type;

    // We must take the guid instead of the id, because duplicate ids
    // across multiple traces will confuse the execution trace reader.
    item.stateId = state->getGuid();

    item.addressSpace = state->regs()->getPageDir();
    item.pc = state->regs()->getPc();

    if (m_Monitor && m_Monitor->initialized()) {
        item.pid = m_Monitor->getPid(state, item.pc);
    } else {
        item.pid = 0;
    }

    if (m_useCircularBuffer) {
        appendToCircularBuffer(&item, data, size);
    } else {
        appendToTraceFile(&item, data, size);
    }

    return ++m_CurrentIndex;
}

bool ExecutionTracer::flushCircularBufferToFile() {
    if (!m_useCircularBuffer) {
        return false;
    }

    foreach2 (it, m_circularBuffer.begin(), m_circularBuffer.end()) {
        const ExecutionTraceAllItems &item = *it;
        appendToTraceFile(&item.header, &item.u, item.header.size);
    }

    m_circularBuffer.clear();

    flush();

    return true;
}

void ExecutionTracer::flush() {
    if (m_LogFile) {
        fflush(m_LogFile);
    }
}

void ExecutionTracer::onProcessFork(bool preFork, bool isChild, unsigned parentProcId) {
    if (preFork) {
        fclose(m_LogFile);
        m_LogFile = NULL;
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
    unsigned itemSize = sizeof(ExecutionTraceFork) + 1 * sizeof(uint32_t);
    uint8_t *itemBytes = new uint8_t[itemSize];
    ExecutionTraceFork *itemFork = reinterpret_cast<ExecutionTraceFork *>(itemBytes);

    itemFork->stateCount = 2;
    itemFork->children[0] = state->getGuid();
    itemFork->children[1] = newGuid;
    writeData(state, itemFork, itemSize, TRACE_FORK);

    delete[] itemBytes;
}

void ExecutionTracer::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                             const std::vector<klee::ref<klee::Expr>> &newConditions) {
    assert(newStates.size() > 0);

    unsigned itemSize = sizeof(ExecutionTraceFork) + (newStates.size() - 1) * sizeof(uint32_t);

    uint8_t *itemBytes = new uint8_t[itemSize];
    ExecutionTraceFork *itemFork = reinterpret_cast<ExecutionTraceFork *>(itemBytes);

    itemFork->stateCount = newStates.size();

    for (unsigned i = 0; i < newStates.size(); i++) {
        itemFork->children[i] = newStates[i]->getGuid();
    }

    writeData(state, itemFork, itemSize, TRACE_FORK);

    delete[] itemBytes;
}

void ExecutionTracer::onMonitorLoad(S2EExecutionState *state) {
    ExecutionTraceOSInfo info;
    info.kernelStart = m_Monitor->getKernelStart();
    writeData(state, &info, sizeof(info), TRACE_OSINFO);
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

    tracer->flushCircularBufferToFile();
    tracer->flush();
}
}
