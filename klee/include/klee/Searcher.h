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

    virtual ExecutionState &selectState() = 0;

    // Clients must first process the addedStates set
    // and then the removedStates set. A state can be included in
    // both sets if it has been added and then removed
    // immediately after. Processing the sets in the wrong order
    // may cause the searcher to return a state that
    // has actually been deleted.
    virtual void update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates) = 0;

    virtual bool empty() = 0;

    // utility functions

    void addState(ExecutionState *es, ExecutionState *current = 0) {
        StateSet tmp;
        tmp.insert(es);
        update(current, tmp, StateSet());
    }

    void removeState(ExecutionState *es, ExecutionState *current = 0) {
        StateSet tmp;
        tmp.insert(es);
        update(current, StateSet(), tmp);
    }
};

class DFSSearcher : public Searcher {
    std::vector<ExecutionState *> states;
    ExecutionState *currentState;

public:
    DFSSearcher() {
        currentState = NULL;
    }

    ExecutionState &selectState();
    void update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates);
    bool empty() {
        return states.empty();
    }
};

class RandomSearcher : public Searcher {
    std::vector<ExecutionState *> states;

public:
    ExecutionState &selectState();
    void update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates);
    bool empty() {
        return states.empty();
    }
};

Searcher *constructUserSearcher();

} // namespace klee

#endif
