///
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "LoopExitSearcher.h"

namespace s2e {
namespace plugins {

using namespace llvm;
using namespace searchers;

S2E_DEFINE_PLUGIN(LoopExitSearcher, "Searcher that prioritizes states that exit loops quicker", "LoopExitSearcher",
                  "LoopDetector", "ControlFlowGraph", "BasicBlockCoverage", "EdgeCoverage");

void LoopExitSearcher::initialize() {
    s2e()->getExecutor()->setSearcher(this);

    m_loopDetector = s2e()->getPlugin<LoopDetector>();
    m_cfg = s2e()->getPlugin<ControlFlowGraph>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_bbcov = s2e()->getPlugin<coverage::BasicBlockCoverage>();
    m_ecov = s2e()->getPlugin<EdgeCoverage>();

    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &LoopExitSearcher::onFork));

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &LoopExitSearcher::onTimer));

    m_currentState = NULL;
    m_timerTicks = 0;
}

void LoopExitSearcher::onTimer() {
    ++m_timerTicks;

    if (m_timerTicks < 10) {
        return;
    }

    m_timerTicks = 0;
    getDebugStream() << "Main queue size: " << m_states.size() << " wait queue size: " << m_waitingStates.size()
                     << "\n";
}

void LoopExitSearcher::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                              const std::vector<klee::ref<klee::Expr>> &newConditions) {
    /**********/
    /* Update the fork count stats */
    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    uint64_t curPc = 0;
    uint64_t currentForkCount = 0;

    if (module) {
        curPc = module->ToNativeBase(state->getPc());
        currentForkCount = ++m_forkCount[module->Name][curPc];
    } else {
        curPc = state->getPc();
        currentForkCount = ++m_forkCount["unknown"][curPc];
    }

    /**********/
    StatesByPointer &byPointer = m_states.get<state_t>();
    StatesByPointer::iterator pit = byPointer.find(state);
    assert(pit != byPointer.end());

    // Every forked state gets the new info
    foreach2 (it2, newStates.begin(), newStates.end()) {
        if (*it2 == state) {
            continue;
        }

        StatePriority p = *pit;
        p.state = *it2;

        /**
         * This location has forked too often, put the child states into
         * a waiting queue.
         */
        if (currentForkCount > 10) {
            m_waitingStates.insert(p);
        } else {
            m_states.insert(p);
        }
    }

    if (!module) {
        return;
    }

    const ControlFlowGraph::BasicBlock *bb = m_cfg->findBasicBlock(module->Name, curPc);
    if (!bb) {
        return;
    }

    getDebugStream(state) << "CurBB: " << hexval(bb->start_pc) << "\n";

    uint64_t staticTargets[2];
    if (!state->getStaticBranchTargets(&staticTargets[0], &staticTargets[1])) {
        return;
    }

    uint64_t targets[2];

    uint64_t header = 0;
    bool isInLoop = m_loopDetector->getLoop(module->Name, bb->start_pc, header);
    if (!isInLoop) {
        return;
    }

    bool doYield = false;

    // The exit blocks get a higher priority
    for (unsigned i = 0; i < 2; ++i) {
        targets[i] = module->ToNativeBase(staticTargets[i]);
        m_bbcov->addNonCoveredBlock(newStates[i], module->Name, targets[i]);
        m_ecov->addNonCoveredEdge(newStates[i], module->Name, bb->end_pc, targets[i]);

        uint64_t finalSucc = targets[i];
        bool isExit = m_loopDetector->isExitBlock(module->Name, finalSucc);

        // Go through a possible chain of direct jumps
        m_cfg->getFinalSuccessor(module->Name, targets[i], &finalSucc);
        isExit |= m_loopDetector->isExitBlock(module->Name, finalSucc);

        // Final successor is either an exit block, belongs to a different loop, or is outside the current loop.
        uint64_t otherloop;
        bool anotherLoop = false;
        if (m_loopDetector->getLoop(module->Name, finalSucc, otherloop)) {
            anotherLoop = otherloop != header;
        }

        llvm::raw_ostream &os = getDebugStream(state);
        os << "Target[" << i << "]:"
           << " state: " << newStates[i]->getID() << " dest:" << hexval(targets[i])
           << " finalsucc: " << hexval(finalSucc) << " isExit: " << (int) isExit
           << " toAnotherLoop: " << (int) anotherLoop << "\n";

        if (isExit || anotherLoop) {
            increasePriority(newStates[i], 1);
            doYield = true;
        }
    }

    if (doYield) {
        s2e()->getExecutor()->yieldState(*state);
    }
}

void LoopExitSearcher::increasePriority(S2EExecutionState *state, int64_t priority) {
    MultiStates *ms[2];
    ms[0] = &m_states;
    ms[1] = &m_waitingStates;

    for (unsigned i = 0; i < 2; ++i) {
        StatesByPointer &byPointer = ms[i]->get<state_t>();
        StatesByPointer::iterator it = byPointer.find(state);
        if (it == byPointer.end()) {
            continue;
        }

        StatePriority p = (*it);
        p.priority += priority;

        getDebugStream(state) << "Increasing priority of state " << state->getID() << " by " << priority
                              << " new: " << p.priority << "\n";

        byPointer.erase(state);
        ms[i]->insert(p);
        return;
    }

    assert(false && "Can't get here");
}

klee::ExecutionState &LoopExitSearcher::selectState() {
    assert(!m_states.empty());

    llvm::DenseSet<S2EExecutionState *> ds;
    S2EExecutionState *nc = m_bbcov->getNonCoveredState(ds);
    if (nc) {
        getDebugStream() << "Found non-covered basic block\n";
        m_currentState = nc;
        return *nc;
    }

    nc = m_ecov->getNonCoveredState(ds);
    if (nc) {
        getDebugStream() << "Found non-covered edge\n";
        m_currentState = nc;
        return *nc;
    }

    if (m_states.empty()) {
        getDebugStream() << "No more states, trying the wait queue\n";
        StatesByPointer &byPointer = m_waitingStates.get<state_t>();
        StatesByPointer::reverse_iterator pit = byPointer.rbegin();
        const StatePriority p = (*pit);
        byPointer.erase(p.state);
        m_states.insert(p);
    }

    StatesByPriority &byPriority = m_states.get<priority_t>();
    StatesByPriority::reverse_iterator it = byPriority.rbegin();
    assert(it != byPriority.rend());

    const StatePriority p = (*it);

    if (!m_currentState) {
        m_currentState = p.state;
        return *m_currentState;
    }

    // Select new state only if it has higher priority than the current one
    StatesByPointer &byPointer = m_states.get<state_t>();
    StatesByPointer::iterator pit = byPointer.find(m_currentState);
    assert(pit != byPointer.end());

    if (p.priority > (*pit).priority) {
        m_currentState = p.state;
    }

    return *m_currentState;
}

void LoopExitSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                              const klee::StateSet &removedStates) {
    /* The forked states will get this priority */
    /* All the added states should be there already (see onFork event) ? */
    foreach2 (ait, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*ait);

        StatesByPointer &byPointer = m_states.get<state_t>();
        StatesByPointer::iterator it = byPointer.find(state);
        if (it == byPointer.end()) {
            StatePriority p(state, 0);
            m_states.insert(p);
        }
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        StatesByPointer &byPointer = m_states.get<state_t>();
        byPointer.erase(state);
        if (state == m_currentState) {
            m_currentState = NULL;
        }
    }
}

bool LoopExitSearcher::empty() {
    return m_states.empty();
}

} // namespace plugins
} // namespace s2e
