//===-- Searcher.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

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

#include "klee/Searcher.h"

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

ExecutionStatePtr DFSSearcher::selectState() {
    assert(m_states.size() && "No states available");
    ExecutionStatePtr ret = m_states.back();

    if (m_currentState == nullptr) {
        m_currentState = ret;
    }

    return m_currentState;
}

void DFSSearcher::addState(ExecutionStatePtr state) {
    m_states.push_back(state);
}

void DFSSearcher::removeState(ExecutionStatePtr state) {
    if (m_currentState == state) {
        m_currentState = nullptr;
    }

    auto it = std::find(m_states.begin(), m_states.end(), state);
    if (it != m_states.end()) {
        m_states.erase(it);
    }
}

///

ExecutionStatePtr RandomSearcher::selectState() {
    assert(m_states.size() && "No states available");
    auto val = uni(rng) % m_states.size();
    return m_states[val];
}

void RandomSearcher::addState(ExecutionStatePtr state) {
    m_states.push_back(state);
}

void RandomSearcher::removeState(ExecutionStatePtr state) {
    auto it = std::find(m_states.begin(), m_states.end(), state);
    if (it != m_states.end()) {
        m_states.erase(it);
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