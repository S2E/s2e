///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "MergingSearcher.h"

namespace s2e {
namespace plugins {

using namespace llvm;

S2E_DEFINE_PLUGIN(MergingSearcher, "Searcher to be used with state merging", "MergingSearcher");

void MergingSearcher::initialize() {
    s2e()->getExecutor()->setSearcher(this);
    m_currentState = nullptr;
    m_nextMergeGroupId = 1;
    m_selector = nullptr;

    m_debug = s2e()->getConfig()->getBool(getConfigKey() + ".debug");
}

klee::ExecutionState &MergingSearcher::selectState() {
    if (m_selector) {
        S2EExecutionState *state = m_selector->selectState();
        assert(m_activeStates.find(state) != m_activeStates.end());
        return *state;
    }

    S2EExecutionState *state = m_currentState;
    if (state) {
        return *state;
    }

    assert(!m_activeStates.empty());

    state = *m_activeStates.begin();
    m_currentState = state;
    return *state;
}

void MergingSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                             const klee::StateSet &removedStates) {
    States states;
    foreach2 (it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        states.insert(state);
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        states.erase(state);
        m_activeStates.erase(state);

        DECLARE_PLUGINSTATE(MergingSearcherState, state);
        if (plgState->getGroupId()) {
            m_mergePools[plgState->getGroupId()].states.erase(state);
        }

        if (state == m_currentState) {
            m_currentState = nullptr;
        }
    }

    foreach2 (it, states.begin(), states.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        m_activeStates.insert(state);

        DECLARE_PLUGINSTATE(MergingSearcherState, state);
        if (plgState->getGroupId()) {
            m_mergePools[plgState->getGroupId()].states.insert(state);
        }
    }

    if (m_selector) {
        m_selector->update(current, addedStates, removedStates);
    }
}

bool MergingSearcher::empty() {
    return m_activeStates.empty();
}

void MergingSearcher::suspend(S2EExecutionState *state) {
    if (m_debug) {
        getDebugStream(nullptr) << "MergingSearcher: "
                                << "suspending state " << state->getID() << "\n";
    }

    if (m_currentState == state) {
        m_currentState = nullptr;
    }

    m_activeStates.erase(state);
    if (m_selector) {
        m_selector->setActive(state, false);
    }
}

void MergingSearcher::resume(S2EExecutionState *state) {
    if (m_debug) {
        getDebugStream(nullptr) << "MergingSearcher: "
                                << "resuming state " << state->getID() << "\n";
    }

    m_activeStates.insert(state);
    if (m_selector) {
        m_selector->setActive(state, true);
    }
}

bool MergingSearcher::mergeStart(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MergingSearcherState, state);

    if (plgState->getGroupId() != 0) {
        getWarningsStream(state) << "MergingSearcher: state id already has group id " << plgState->getGroupId() << "\n";
        return false;
    }

    uint64_t id = m_nextMergeGroupId++;

    if (m_debug) {
        getWarningsStream(state) << "MergingSearcher: starting merge group " << id << "\n";
    }

    plgState->setGroupId(id);
    m_mergePools[id].states.insert(state);
    state->setPinned(true);
    return true;
}

bool MergingSearcher::mergeEnd(S2EExecutionState *state, bool skipOpcode, bool clearTmpFlags) {
    DECLARE_PLUGINSTATE(MergingSearcherState, state);

    if (m_debug) {
        getWarningsStream(state) << "MergingSearcher: merging state\n";
    }

    MergePools::iterator it = m_mergePools.find(plgState->getGroupId());
    if (it == m_mergePools.end()) {
        getWarningsStream(state) << "MergingSearcher: state does not belong to a merge group\n";
        return false;
    }

    merge_pool_t &mergePool = (*it).second;

    mergePool.states.erase(state);
    if (mergePool.states.empty() && !mergePool.firstState) {
        // No states forked in the merge pool when the merge point was reached,
        // so there is nothing to merge and therefore we return.
        plgState->setGroupId(0);
        m_mergePools.erase(it);
        state->setPinned(false);
        return true;
    }

    // Skip the opcode
    if (skipOpcode) {
        state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->regs()->getPc() + 10);
    }

    // Clear temp flags.
    // This assumes we were called through the custom instructions,
    // implying that the flags can be clobbered.
    // XXX: is it possible that these can be symbolic?
    if (clearTmpFlags) {
        state->regs()->write(CPU_OFFSET(cc_op), 0);
        state->regs()->write(CPU_OFFSET(cc_src), 0);
        state->regs()->write(CPU_OFFSET(cc_dst), 0);
        state->regs()->write(CPU_OFFSET(cc_tmp), 0);
    }

    // The TLB state must be identical when we merge
    tlb_flush(env, 1);

    if (!mergePool.firstState) {
        // state is the first to reach merge_end.
        // all other states that reach merge_end will be merged with it and destroyed
        // first_state accumulates all the merges
        mergePool.firstState = state;
        suspend(state);
        state->yield();
        pabort("Can't get here");
        return false;
    }

    bool success = g_s2e->getExecutor()->merge(*mergePool.firstState, *state);

    if (mergePool.states.empty()) {
        resume(mergePool.firstState);
        DECLARE_PLUGINSTATE(MergingSearcherState, mergePool.firstState);
        plgState->setGroupId(0);
        mergePool.firstState->setPinned(false);
        m_mergePools.erase(it);
    }

    if (success) {
        g_s2e->getExecutor()->terminateState(*state, "Killed by merge");
    } else {
        plgState->setGroupId(0);
        getDebugStream(state) << "Merge failed\n";
    }

    // Symbolic state may be changed, need to restart
    throw CpuExitException();
}

void MergingSearcher::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    merge_desc_t command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "MergingSearcher: mismatched merge_desc_t size"
                                 << " got " << guestDataSize << " expected " << sizeof(command) << "\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "MergingSearcher: could not read transmitted data\n";
        return;
    }

    if (command.start) {
        mergeStart(state);
    } else {
        mergeEnd(state, true, true);
    }
}

MergingSearcherState::MergingSearcherState() {
    m_groupId = 0;
}

MergingSearcherState::~MergingSearcherState() {
}

MergingSearcherState *MergingSearcherState::clone() const {
    return new MergingSearcherState(*this);
}

PluginState *MergingSearcherState::factory(Plugin *p, S2EExecutionState *s) {
    return new MergingSearcherState();
}

} // namespace plugins
} // namespace s2e
