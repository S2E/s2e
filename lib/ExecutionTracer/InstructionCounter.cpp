///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "InstructionCounter.h"
#include <cassert>
#include <iomanip>
#include <iostream>

using namespace s2e::plugins;

namespace s2etools {

InstructionCounter::InstructionCounter(LogEvents *events) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &InstructionCounter::onItem));
}

InstructionCounter::~InstructionCounter() {
    m_connection.disconnect();
}

void InstructionCounter::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type != s2e::plugins::TRACE_ICOUNT) {
        return;
    }

    ExecutionTraceICount *e = static_cast<ExecutionTraceICount *>(item);
    InstructionCounterState *state =
        static_cast<InstructionCounterState *>(m_events->getState(this, &InstructionCounterState::factory));

#ifdef DEBUG_PB
    std::cout << "ID=" << traceIndex << " ICOUNT: e=" << e->count << " state=" << state->m_icount << " item=" << item
              << std::endl;
#endif

    assert(e->count >= state->m_icount);
    state->m_icount = e->count;
}

void InstructionCounterState::printCounter(std::ostream &os) {
    os << "Instruction count: " << std::dec << m_icount << std::endl;
}

ItemProcessorState *InstructionCounterState::factory() {
    return new InstructionCounterState();
}

InstructionCounterState::InstructionCounterState() {
    m_icount = 0;
}

InstructionCounterState::~InstructionCounterState() {
}

ItemProcessorState *InstructionCounterState::clone() const {
    return new InstructionCounterState(*this);
}
}
