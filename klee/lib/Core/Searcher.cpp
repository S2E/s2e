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

#include "klee/Executor.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/System/Time.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"

#include <cassert>
#include <climits>
#include <fstream>
#include <random>

using namespace llvm;

namespace {
cl::opt<bool> UseDfsSearch("use-dfs-search");
cl::opt<bool> UseRandomSearch("use-random-search");

std::random_device rd;
std::mt19937 rng(rd());
std::uniform_int_distribution<uint32_t> uni(0, UINT32_MAX);

} // namespace

namespace klee {

Searcher::~Searcher() {
}

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

            if (!ok) {
                pabort("invalid state removed");
            }
        }
    }

    if (firstTime) {
        currentState = states[0];
    }
}

///

ExecutionState &RandomSearcher::selectState() {
    auto val = uni(rng) % states.size();
    return *states[val];
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

        if (!ok) {
            pabort("invalid state removed");
        }
    }
}

Searcher *constructUserSearcher() {
    Searcher *searcher = 0;

    if (UseRandomSearch) {
        searcher = new RandomSearcher();
    } else if (UseDfsSearch) {
        searcher = new DFSSearcher();
    } else {
        searcher = new DFSSearcher();
    }

    return searcher;
}

} // namespace klee