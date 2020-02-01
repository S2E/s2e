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

#include <map>
#include <queue>
#include <set>
#include <vector>

// FIXME: Move out of header, use llvm streams.
#include <klee/Common.h>
#include <ostream>

#include <inttypes.h>

namespace llvm {
class BasicBlock;
class Function;
class Instruction;
} // namespace llvm

namespace klee {
class ExecutionState;
class Executor;

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

    // prints name of searcher as a klee_message()
    // TODO: could probably make prettier or more flexible
    virtual void printName(llvm::raw_ostream &os) {
        os << "<unnamed searcher>\n";
    }

    // pgbovine - to be called when a searcher gets activated and
    // deactivated, say, by a higher-level searcher; most searchers
    // don't need this functionality, so don't have to override.
    virtual void activate(){};
    virtual void deactivate(){};

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
    void printName(llvm::raw_ostream &os) {
        os << "DFSSearcher\n";
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
    void printName(llvm::raw_ostream &os) {
        os << "RandomSearcher\n";
    }
};

class BatchingSearcher : public Searcher {
    Searcher *baseSearcher;
    uint64_t timeBudget;
    unsigned instructionBudget;

    ExecutionState *lastState;
    uint64_t lastStartTime;
    unsigned lastStartInstructions;

public:
    BatchingSearcher(Searcher *baseSearcher, uint64_t _timeBudget, unsigned _instructionBudget);
    ~BatchingSearcher();

    ExecutionState &selectState();
    void update(ExecutionState *current, const StateSet &addedStates, const StateSet &removedStates);
    bool empty() {
        return baseSearcher->empty();
    }
    void printName(llvm::raw_ostream &os) {
        os << "<BatchingSearcher> timeBudget: " << timeBudget << ", instructionBudget: " << instructionBudget
           << ", baseSearcher:\n";
        baseSearcher->printName(os);
        os << "</BatchingSearcher>\n";
    }
};
} // namespace klee

#endif
