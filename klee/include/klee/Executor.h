//===-- Executor.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Class to perform actual execution, hides implementation details from external
// interpreter.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXECUTOR_H
#define KLEE_EXECUTOR_H

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "klee/Common.h"
#include "klee/ExecutionState.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"

namespace llvm {
class BasicBlock;
class BranchInst;
class CallInst;
class Constant;
class ConstantExpr;
class Function;
class GlobalValue;
class Instruction;
class TargetData;
class Twine;
class Value;
class LLVMContext;
} // namespace llvm

namespace klee {
class Array;
struct Cell;
class ExecutionState;
class ExternalDispatcher;
class Expr;
struct KInstruction;
class KInstIterator;
class KModule;
class ObjectState;
class Searcher;
class SpecialFunctionHandler;
struct StackFrame;
class TimingSolver;
class BitfieldSimplifier;
class SolverFactory;
template <class T> class ref;

class Executor {
public:
    typedef std::pair<ExecutionState *, ExecutionState *> StatePair;

protected:
    KModulePtr kmodule;
    Searcher *searcher;

    ExternalDispatcher *externalDispatcher;
    StateSet states;
    SpecialFunctionHandler *specialFunctionHandler;

    /// Used to track states that have been added during the current
    /// instructions step.
    /// \invariant \ref addedStates is a subset of \ref states.
    /// \invariant \ref addedStates and \ref removedStates are disjoint.
    StateSet addedStates;
    /// Used to track states that have been removed during the current
    /// instructions step.
    /// \invariant \ref removedStates is a subset of \ref states.
    /// \invariant \ref addedStates and \ref removedStates are disjoint.
    StateSet removedStates;

    /// Map of predefined global values
    std::map<std::string, void *> predefinedSymbols;

    /// Map of globals to their representative memory object.
    std::map<const llvm::GlobalValue *, ObjectKey> globalObjects;

    /// Map of globals to their bound address. This also includes
    /// globals that have no representative object (i.e. functions).
    GlobalAddresses globalAddresses;

    /// The set of functions that must be handled via custom function handlers
    /// instead of being called directly.
    std::set<llvm::Function *> overridenInternalFunctions;

    llvm::Function *getTargetFunction(llvm::Value *calledVal);

    void executeInstruction(ExecutionState &state, KInstruction *ki);

    void initializeGlobalObject(ExecutionState &state, const ObjectStatePtr &os, const llvm::Constant *c,
                                unsigned offset);
    void initializeGlobals(ExecutionState &state);

    virtual void updateStates(ExecutionState *current);

    void callExternalFunction(ExecutionState &state, KInstruction *target, llvm::Function *function,
                              std::vector<ref<Expr>> &arguments);

    void executeCall(ExecutionState &state, KInstruction *ki, llvm::Function *f, std::vector<ref<Expr>> &arguments);

    ref<Expr> executeMemoryOperation(ExecutionState &state, bool isWrite, uint64_t concreteAddress,
                                     ref<Expr> value /* undef if read */, unsigned bytes);

    // do address resolution / object binding / out of bounds checking
    // and perform the operation
    void executeMemoryOperation(ExecutionState &state, bool isWrite, ref<Expr> address,
                                ref<Expr> value /* undef if read */, KInstruction *target /* undef if write */);

    /// The current state is about to be branched.
    /// Give a chance to S2E to checkpoint the current device state
    /// so that the branched state gets it as well.
    virtual void notifyBranch(ExecutionState &state);

    /// When the fork is complete and state properly updated,
    /// notify the S2EExecutor, so that it can generate an onFork event.
    /// Sending notification after the fork completed
    /// allows plugins to kill states and exit to the CPU loop safely.
    virtual void notifyFork(ExecutionState &originalState, ref<Expr> &condition, Executor::StatePair &targets);

    const Cell &eval(KInstruction *ki, unsigned index, ExecutionState &state) const;

    // delete the state (called internally by terminateState and updateStates)
    virtual void deleteState(ExecutionState *state);

    void handlePointsToObj(ExecutionState &state, KInstruction *target, const std::vector<ref<Expr>> &arguments);

    typedef void (*FunctionHandler)(Executor *executor, ExecutionState *state, KInstruction *target,
                                    std::vector<ref<Expr>> &arguments);

    /// Add a special function handler
    void addSpecialFunctionHandler(llvm::Function *function, FunctionHandler handler);

public:
    Executor(llvm::LLVMContext &context);
    virtual ~Executor();

    // Fork current and return states in which condition holds / does
    // not hold, respectively. One of the states is necessarily the
    // current state, and one of the states may be null.
    //
    // keepConditionTrueInCurrentState makes sure original state will have condition equal true.
    // This is useful when forking one state with several different values.
    // NOTE: In concolic mode it will recompute initial values for current state, do not use it for seed state.
    virtual StatePair fork(ExecutionState &current, const ref<Expr> &condition,
                           bool keepConditionTrueInCurrentState = false);

    // Unconditional fork
    virtual StatePair fork(ExecutionState &current);

    // remove state from queue and delete
    virtual void terminateState(ExecutionState &state);

    virtual void terminateState(ExecutionState &state, const std::string &reason);

    virtual const llvm::Module *setModule(llvm::Module *module);

    /*** State accessor methods ***/
    size_t getStatesCount() const {
        return states.size();
    }
    const StateSet &getStates() {
        return states;
    }

    const StateSet &getAddedStates() {
        return addedStates;
    }

    const StateSet &getRemovedStates() {
        return removedStates;
    }

    ExternalDispatcher *getDispatcher() const {
        return externalDispatcher;
    }

    KModulePtr getModule() const {
        return kmodule;
    }
};

} // namespace klee

#endif
