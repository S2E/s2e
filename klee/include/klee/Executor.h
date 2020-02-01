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
#include "klee/ExecutionState.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Interpreter.h"
#include "llvm/IR/CallSite.h"

#include "klee/Common.h"

struct KTest;

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
} // namespace llvm

namespace klee {
class Array;
struct Cell;
class ExecutionState;
class ExternalDispatcher;
class Expr;
struct KFunction;
struct KInstruction;
class KInstIterator;
class KModule;
class ObjectState;
class PTree;
class Searcher;
class SpecialFunctionHandler;
struct StackFrame;
class StatsTracker;
class TimingSolver;
class BitfieldSimplifier;
class SolverFactory;
template <class T> class ref;

/// \todo Add a context object to keep track of data only live
/// during an instruction step. Should contain addedStates,
/// removedStates, and haltExecution, among others.

class Executor : public Interpreter {
    friend class BumpMergingSearcher;
    friend class MergingSearcher;
    friend class RandomPathSearcher;
    friend class OwningSearcher;
    friend class WeightedRandomSearcher;
    friend class SpecialFunctionHandler;
    friend class StatsTracker;

public:
    class Timer {
    public:
        Timer();
        virtual ~Timer();

        /// The event callback.
        virtual void run() = 0;
    };

    typedef std::pair<ExecutionState *, ExecutionState *> StatePair;

protected:
    class TimerInfo;

    KModule *kmodule;
    InterpreterHandler *interpreterHandler;
    Searcher *searcher;

    ExternalDispatcher *externalDispatcher;
    StateSet states;
    StatsTracker *statsTracker;
    SpecialFunctionHandler *specialFunctionHandler;
    std::vector<TimerInfo *> timers;

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
    std::unordered_map<const llvm::GlobalValue *, ref<ConstantExpr>> globalAddresses;

    /// The set of functions that must be handled via custom function handlers
    /// instead of being called directly.
    std::set<llvm::Function *> overridenInternalFunctions;

    llvm::Function *getCalledFunction(llvm::CallSite &cs, ExecutionState &state);

    void executeInstruction(ExecutionState &state, KInstruction *ki);

    void initializeGlobalObject(ExecutionState &state, const ObjectStatePtr &os, llvm::Constant *c, unsigned offset);
    void initializeGlobals(ExecutionState &state);

    virtual void updateStates(ExecutionState *current);
    void transferToBasicBlock(llvm::BasicBlock *dst, llvm::BasicBlock *src, ExecutionState &state);

    void callExternalFunction(ExecutionState &state, KInstruction *target, llvm::Function *function,
                              std::vector<ref<Expr>> &arguments);

    /// Allocate and bind a new object in a particular state. NOTE: This
    /// function may fork.
    ///
    /// \param isLocal Flag to indicate if the object should be
    /// automatically deallocated on function return (this also makes it
    /// illegal to free directly).
    ///
    /// \param target Value at which to bind the base address of the new
    /// object.
    ///
    /// \param reallocFrom If non-zero and the allocation succeeds,
    /// initialize the new object from the given one and unbind it when
    /// done (realloc semantics). The initialized bytes will be the
    /// minimum of the size of the old and new objects, with remaining
    /// bytes initialized as specified by zeroMemory.
    void executeAlloc(ExecutionState &state, ref<Expr> size, bool isLocal, KInstruction *target,
                      bool zeroMemory = false, const ObjectStatePtr &reallocFrom = nullptr);

    void executeCall(ExecutionState &state, KInstruction *ki, llvm::Function *f, std::vector<ref<Expr>> &arguments);

    template <typename T>
    void writeAndNotify(ExecutionState &state, const ObjectStatePtr &wos, T address, ref<Expr> &value);

    ref<Expr> executeMemoryOperationOverlapped(ExecutionState &state, bool isWrite, uint64_t concreteAddress,
                                               ref<Expr> value /* undef if read */, unsigned bytes);

    // This is the actual read/write function, called after the target
    // object was determined.
    ref<Expr> executeMemoryOperation(ExecutionState &state, const ObjectStateConstPtr &os, bool isWrite,
                                     uint64_t offset, ref<Expr> value /* undef if read */, Expr::Width type);

    ref<Expr> executeMemoryOperation(ExecutionState &state, const ObjectStateConstPtr &os, bool isWrite,
                                     ref<Expr> offset, ref<Expr> value /* undef if read */, Expr::Width type);

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

    ref<klee::ConstantExpr> evalConstantExpr(const llvm::ConstantExpr *ce, const KInstruction *ki = nullptr);

    // delete the state (called internally by terminateState and updateStates)
    virtual void deleteState(ExecutionState *state);

    /// bindModuleConstants - Initialize the module constant table.
    void bindModuleConstants();

    template <typename TypeIt> void computeOffsets(KGEPInstruction *kgepi, TypeIt ib, TypeIt ie);

    /// bindInstructionConstants - Initialize any necessary per instruction
    /// constant values.
    void bindInstructionConstants(KInstruction *KI);

    void handlePointsToObj(ExecutionState &state, KInstruction *target, const std::vector<ref<Expr>> &arguments);

    /// Add a timer to be executed periodically.
    ///
    /// \param timer The timer object to run on firings.
    /// \param rate The approximate delay (in seconds) between firings.
    void addTimer(Timer *timer, double rate);

    static void onAlarm(int);
    virtual void setupTimersHandler();
    void initTimers();
    void processTimers(ExecutionState *current);

    typedef void (*FunctionHandler)(Executor *executor, ExecutionState *state, KInstruction *target,
                                    std::vector<ref<Expr>> &arguments);

    /// Add a special function handler
    void addSpecialFunctionHandler(llvm::Function *function, FunctionHandler handler);

public:
    Executor(InterpreterHandler *ie, llvm::LLVMContext &context);
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

    // remove state from queue and delete
    virtual void terminateState(ExecutionState &state);

    virtual void terminateState(ExecutionState &state, const std::string &reason);

    // XXX should just be moved out to utility module
    ref<klee::ConstantExpr> evalConstant(const llvm::Constant *c, const KInstruction *ki = nullptr);

    virtual const llvm::Module *setModule(llvm::Module *module, const ModuleOptions &opts,
                                          bool createStatsTracker = true);

    // Given a concrete object in our [klee's] address space, add it to
    // objects checked code can reference.
    ObjectStatePtr addExternalObject(ExecutionState &state, void *addr, unsigned size, bool isReadOnly,
                                     bool isSharedConcrete = false);

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

    Expr::Width getWidthForLLVMType(llvm::Type *type) const;

    ExternalDispatcher *getDispatcher() const {
        return externalDispatcher;
    }

    KModule *getModule() const {
        return kmodule;
    }
};

} // namespace klee

#endif
