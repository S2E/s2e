//===-- Searcher.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_SEARCHER_H
#define KLEE_SEARCHER_H

#include <vector>

// FIXME: Move out of header, use llvm streams.
#include <klee/Common.h>

namespace klee {
class ExecutionState;

class Searcher {
public:
    virtual ~Searcher();

    virtual ExecutionStatePtr selectState() = 0;

    virtual bool empty() = 0;

    virtual void addState(klee::ExecutionStatePtr state) = 0;
    virtual void removeState(klee::ExecutionStatePtr state) = 0;
};

class DFSSearcher : public Searcher {
    std::vector<ExecutionStatePtr> m_states;
    ExecutionStatePtr m_currentState;

public:
    ExecutionStatePtr selectState();

    virtual void addState(klee::ExecutionStatePtr state);
    virtual void removeState(klee::ExecutionStatePtr state);

    bool empty() {
        return m_states.empty();
    }
};

class RandomSearcher : public Searcher {
    std::vector<ExecutionStatePtr> m_states;

public:
    ExecutionStatePtr selectState();
    virtual void addState(klee::ExecutionStatePtr state);
    virtual void removeState(klee::ExecutionStatePtr state);
    bool empty() {
        return m_states.empty();
    }
};

Searcher *constructUserSearcher();

} // namespace klee

#endif
