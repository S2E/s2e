///
/// Copyright (C) 2011-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/**
 * This plugin implements a cooperative searcher.
 * The current state is run until the running program expicitely
 * asks to schedule another one, akin to cooperative scheduling.
 *
 * This searcher is useful for debugging S2E, becauses it allows
 * to control the sequence of executed states.
 *
 * RESERVES THE CUSTOM OPCODE 0xAB
 */

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "CooperativeSearcher.h"

namespace s2e {
namespace plugins {

using namespace llvm;

S2E_DEFINE_PLUGIN(CooperativeSearcher, "Uses custom instructions to schedule states", "CooperativeSearcher");

void CooperativeSearcher::initialize() {
    m_searcherInited = false;
    m_currentState = NULL;
    initializeSearcher();
}

void CooperativeSearcher::initializeSearcher() {
    if (m_searcherInited) {
        return;
    }

    s2e()->getExecutor()->setSearcher(this);
    m_searcherInited = true;

    s2e()->getCorePlugin()->onCustomInstruction.connect(
        sigc::mem_fun(*this, &CooperativeSearcher::onCustomInstruction));
}

klee::ExecutionState &CooperativeSearcher::selectState() {
    if (m_currentState) {
        return *m_currentState;
    }

    if (m_states.size() > 0) {
        return *(*m_states.begin()).second;
    }

    assert(false && "There are no states to select!");
}

void CooperativeSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                                 const klee::StateSet &removedStates) {
    foreach2 (it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states[es->getID()] = es;
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.erase(es->getID());

        if (m_currentState == es) {
            m_currentState = NULL;
        }
    }

    if (m_currentState == NULL && m_states.size() > 0) {
        m_currentState = (*m_states.begin()).second;
    }
}

bool CooperativeSearcher::empty() {
    return m_states.empty();
}

void CooperativeSearcher::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    // XXX: find a better way of allocating custom opcodes
    if (!OPCODE_CHECK(opcode, COOPSEARCHER_OPCODE)) {
        return;
    }

    // XXX: remove this mess. Should have a function for extracting
    // info from opcodes.
    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;

    bool ok = true;
    target_ulong nextState = 0;

    CoopSchedulerOpcodes opc = (CoopSchedulerOpcodes) op;
    switch (opc) {
        // Pick the next state specified by the EAX register
        case ScheduleNext: {
            ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &nextState, sizeof nextState);
            if (!ok) {
                getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                            "CooperativeSearcher ScheduleNext"
                                         << '\n';
                break;
            }

            States::iterator it = m_states.find(nextState);
            if (it == m_states.end()) {
                getWarningsStream(state) << "ERROR: Invalid state passed to "
                                         << "CooperativeSearcher ScheduleNext: " << nextState << '\n';
            }

            m_currentState = (*it).second;

            getInfoStream(state) << "CooperativeSearcher picked the state " << nextState << '\n';

            // Force rescheduling
            state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->getPc() + 10);
            throw CpuExitException();
            break;
        }

        // Deschedule the current state. Will pick the state with strictly lower id.
        case Yield: {
            if (m_states.size() == 1) {
                break;
            }

            States::iterator it = m_states.find(m_currentState->getID());
            if (it == m_states.begin()) {
                m_currentState = (*m_states.rbegin()).second;
            } else {
                --it;
                m_currentState = (*it).second;
            }

            // Force rescheduling
            state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->getPc() + 10);
            throw CpuExitException();
            break;
        }
    }
}

} // namespace plugins
} // namespace s2e
