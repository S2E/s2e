///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cassert>
#include <iomanip>
#include <iostream>

#include "ModuleParser.h"
#include "PageFault.h"

using namespace s2e::plugins;

namespace s2etools {

PageFault::PageFault(LogEvents *events, ModuleCache *mc) {
    m_trackModule = false;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &PageFault::onItem));
    m_events = events;
    m_mc = mc;
}

PageFault::~PageFault() {
    m_connection.disconnect();
}

void PageFault::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type == s2e::plugins::TRACE_PAGEFAULT) {
        PageFaultState *state = static_cast<PageFaultState *>(m_events->getState(this, &PageFaultState::factory));

        ExecutionTracePageFault *pageFault = (ExecutionTracePageFault *) item;
        if (m_trackModule) {
            ModuleCacheState *mcs =
                static_cast<ModuleCacheState *>(m_events->getState(m_mc, &ModuleCacheState::factory));
            const ModuleInstance *mi = mcs->getInstance(hdr.pid, pageFault->pc);
            if (!mi || mi->Name != m_module) {
                return;
            }
            state->m_totalPageFaults++;
        } else {
            state->m_totalPageFaults++;
        }
    } else

        if (hdr.type == s2e::plugins::TRACE_TLBMISS) {
        PageFaultState *state = static_cast<PageFaultState *>(m_events->getState(this, &PageFaultState::factory));

        ExecutionTracePageFault *tlbMiss = (ExecutionTracePageFault *) item;
        if (m_trackModule) {
            ModuleCacheState *mcs =
                static_cast<ModuleCacheState *>(m_events->getState(m_mc, &ModuleCacheState::factory));
            const ModuleInstance *mi = mcs->getInstance(hdr.pid, tlbMiss->pc);
            if (!mi || mi->Name != m_module) {
                return;
            }
            state->m_totalTlbMisses++;
        } else {
            state->m_totalTlbMisses++;
        }
    }
}

ItemProcessorState *PageFaultState::factory() {
    return new PageFaultState();
}

PageFaultState::PageFaultState() {
    m_totalPageFaults = 0;
    m_totalTlbMisses = 0;
}

PageFaultState::~PageFaultState() {
}

ItemProcessorState *PageFaultState::clone() const {
    return new PageFaultState(*this);
}
}
