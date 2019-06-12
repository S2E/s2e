//===-- Searcher.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/Searcher.h"

#include "klee/CoreStats.h"
#include "klee/Executor.h"
#include "klee/PTree.h"
#include "klee/StatsTracker.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/ADT/RNG.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/System/Time.h"
#include "klee/Statistics.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"

#include <cassert>
#include <climits>
#include <fstream>

using namespace klee;
using namespace llvm;

namespace klee {
extern RNG theRNG;
}

Searcher::~Searcher() {
}

///

ExecutionState &DFSSearcher::selectState() {
    ExecutionState *ret = states.back();

    if (currentState == NULL) {
        currentState = ret;
    }

    return *currentState;
}

void DFSSearcher::update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates) {
    bool firstTime = states.size() == 0;
    states.insert(states.end(), addedStates.begin(), addedStates.end());
    for (StateSet::const_iterator it = removedStates.begin(), ie = removedStates.end(); it != ie; ++it) {
        ExecutionState *es = *it;
        if (currentState == es) {
            currentState = NULL;
        }

        if (es == states.back()) {
            states.pop_back();
        } else {
            bool ok = false;

            for (std::vector<ExecutionState *>::iterator it = states.begin(), ie = states.end(); it != ie; ++it) {
                if (es == *it) {
                    states.erase(it);
                    ok = true;
                    break;
                }
            }

            assert(ok && "invalid state removed");
        }
    }

    if (firstTime) {
        currentState = states[0];
    }
}

///

ExecutionState &RandomSearcher::selectState() {
    return *states[theRNG.getInt32() % states.size()];
}

void RandomSearcher::update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates) {
    states.insert(states.end(), addedStates.begin(), addedStates.end());
    for (StateSet::const_iterator it = removedStates.begin(), ie = removedStates.end(); it != ie; ++it) {
        ExecutionState *es = *it;
        bool ok = false;

        for (std::vector<ExecutionState *>::iterator it = states.begin(), ie = states.end(); it != ie; ++it) {
            if (es == *it) {
                states.erase(it);
                ok = true;
                break;
            }
        }

        assert(ok && "invalid state removed");
    }
}

///

BatchingSearcher::BatchingSearcher(Searcher *_baseSearcher, uint64_t _timeBudget, unsigned _instructionBudget)
    : baseSearcher(_baseSearcher), timeBudget(_timeBudget), instructionBudget(_instructionBudget), lastState(0) {
}

BatchingSearcher::~BatchingSearcher() {
    delete baseSearcher;
}

extern volatile uint64_t g_timer_ticks;

ExecutionState &BatchingSearcher::selectState() {

    if (!lastState || ((timeBudget > 0) && ((g_timer_ticks - lastStartTime) > timeBudget))) {

        ExecutionState *newState = &baseSearcher->selectState();
        if (newState != lastState) {
            lastState = newState;
            lastStartTime = g_timer_ticks;
            lastStartInstructions = stats::instructions;
        }
        return *newState;
    } else {
        return *lastState;
    }
}

void BatchingSearcher::update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates) {
    if (removedStates.count(lastState))
        lastState = 0;
    baseSearcher->update(current, addedStates, removedStates);
}
