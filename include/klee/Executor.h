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
}

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
class MemoryManager;
class MemoryObject;
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
    SolverFactory *solverFactory;
    std::unordered_map<const ExecutionState *, TimingSolver *> perStateSolvers;
    MemoryManager *memory;
    StateSet states;
    StatsTracker *statsTracker;
    SpecialFunctionHandler *specialFunctionHandler;
    std::vector<TimerInfo *> timers;
    PTree *processTree;
    bool concolicMode;

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
    std::map<const llvm::GlobalValue *, MemoryObject *> globalObjects;

    /// Map of globals to their bound address. This also includes
    /// globals that have no representative object (i.e. functions).
    std::tr1::unordered_map<const llvm::GlobalValue *, ref<ConstantExpr>> globalAddresses;

    /// The set of legal function addresses, used to validate function
    /// pointers. We use the actual Function* address as the function address.
    std::tr1::unordered_set<uint64_t> legalFunctions;

    /// The set of functions that must be handled via custom function handlers
    /// instead of being called directly.
    std::set<llvm::Function *> overridenInternalFunctions;

    /// Whether implied-value concretization is enabled. Currently
    /// false, it is buggy (it needs to validate its writes).
    bool ivcEnabled;

    /// The maximum time to allow for a single solver query.
    double solverTimeout;

    /// Simplifier user to simplify expressions when adding them
    BitfieldSimplifier *exprSimplifier;

    llvm::Function *getCalledFunction(llvm::CallSite &cs, ExecutionState &state);

    void executeInstruction(ExecutionState &state, KInstruction *ki);

    void initializeGlobalObject(ExecutionState &state, ObjectState *os, llvm::Constant *c, unsigned offset);
    void initializeGlobals(ExecutionState &state);

    void stepInstruction(ExecutionState &state);
    virtual void updateStates(ExecutionState *current);
    void transferToBasicBlock(llvm::BasicBlock *dst, llvm::BasicBlock *src, ExecutionState &state);

    void callExternalFunction(ExecutionState &state, KInstruction *target, llvm::Function *function,
                              std::vector<ref<Expr>> &arguments);

    ObjectState *bindObjectInState(ExecutionState &state, const MemoryObject *mo, bool isLocal, const Array *array = 0);

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
                      bool zeroMemory = false, const ObjectState *reallocFrom = 0);

    void executeCall(ExecutionState &state, KInstruction *ki, llvm::Function *f, std::vector<ref<Expr>> &arguments);

    void writeAndNotify(ExecutionState &state, ObjectState *wos, ref<Expr> &address, ref<Expr> &value);

    ref<Expr> executeMemoryOperationOverlapped(ExecutionState &state, bool isWrite, uint64_t concreteAddress,
                                               ref<Expr> value /* undef if read */, unsigned bytes);

    // This is the actual read/write function, called after the target
    // object was determined.
    ref<Expr> executeMemoryOperation(ExecutionState &state, const ObjectPair &op, bool isWrite, ref<Expr> offset,
                                     ref<Expr> value /* undef if read */, Expr::Width type, unsigned bytes);

    // do address resolution / object binding / out of bounds checking
    // and perform the operation
    void executeMemoryOperation(ExecutionState &state, bool isWrite, ref<Expr> address,
                                ref<Expr> value /* undef if read */, KInstruction *target /* undef if write */);

    /// Create a new state where each input condition has been added as
    /// a constraint and return the results. The input state is included
    /// as one of the results. Note that the output vector may included
    /// NULL pointers for states which were unable to be created.
    virtual void branch(ExecutionState &state, const std::vector<ref<Expr>> &conditions,
                        std::vector<ExecutionState *> &result);

    /// The current state is about to be branched.
    /// Give a chance to S2E to checkpoint the current device state
    /// so that the branched state gets it as well.
    virtual void notifyBranch(ExecutionState &state);

    /// When the fork is complete and state properly updated,
    /// notify the S2EExecutor, so that it can generate an onFork event.
    /// Sending notification after the fork completed
    /// allows plugins to kill states and exit to the CPU loop safely.
    virtual void notifyFork(ExecutionState &originalState, ref<Expr> &condition, Executor::StatePair &targets);

    /// Add the given (boolean) condition as a constraint on state. This
    /// function is a wrapper around the state's addConstraint function
    /// which also manages manages propagation of implied values and
    /// validity checks.
    void addConstraint(ExecutionState &state, ref<Expr> condition);

    const Cell &eval(KInstruction *ki, unsigned index, ExecutionState &state) const;

    Cell &getArgumentCell(ExecutionState &state, KFunction *kf, unsigned index) {
        // *klee::klee_warning_stream << std::dec << "arg idx="<< index<< " "  << kf->getArgRegister(index) << '\n';
        return state.stack.back().locals[kf->getArgRegister(index)];
    }

    Cell &getDestCell(ExecutionState &state, KInstruction *target) {
        // *klee_warning_stream << "dst Td="<< std::dec << target->dest << '\n';
        return state.stack.back().locals[target->dest];
    }

    void bindLocal(KInstruction *target, ExecutionState &state, ref<Expr> value);
    void bindArgument(KFunction *kf, unsigned index, ExecutionState &state, ref<Expr> value);

    ref<klee::ConstantExpr> evalConstantExpr(llvm::ConstantExpr *ce);

    /// Get textual information regarding a memory address.
    std::string getAddressInfo(ExecutionState &state, ref<Expr> address) const;

    // delete the state (called internally by terminateState and updateStates)
    virtual void deleteState(ExecutionState *state);

    /// bindModuleConstants - Initialize the module constant table.
    void bindModuleConstants();

    /// bindInstructionConstants - Initialize any necessary per instruction
    /// constant values.
    void bindInstructionConstants(KInstruction *KI);

    void handlePointsToObj(ExecutionState &state, KInstruction *target, const std::vector<ref<Expr>> &arguments);

    void doImpliedValueConcretization(ExecutionState &state, ref<Expr> e, ref<ConstantExpr> value);

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

    ref<Expr> simplifyExpr(const ExecutionState &state, ref<Expr> e);

    TimingSolver *createTimingSolver();
    void createStateSolver(const ExecutionState &state);
    void removeStateSolvers();

    TimingSolver *_solver(const ExecutionState &state) const;

    // Fork current and return states in which condition holds / does
    // not hold, respectively. One of the states is necessarily the
    // current state, and one of the states may be null.
    //
    // deterministic tells whether or not to randomize forks in case forking is disabled.
    // XXX: this is only meant to make executeMemoryOperation's life easier.
    //
    // keepConditionTrueInCurrentState makes sure original state will have condition equal true.
    // This is useful when forking one state with several different values.
    // NOTE: In concolic mode it will recompute initial values for current state, do not use it for seed state.
    virtual StatePair fork(ExecutionState &current, ref<Expr> condition, bool isInternal, bool deterministic = false,
                           bool keepConditionTrueInCurrentState = false);

    // keepConditionTrueInCurrentState makes sure original state will have condition equal true.
    // This is useful when forking one state with several different values.
    // NOTE: In concolic mode it will recompute initial values for current state, do not use it for seed state.
    virtual StatePair concolicFork(ExecutionState &current, ref<Expr> condition, bool isInternal,
                                   bool keepConditionTrueInCurrentState = false);

public:
    Executor(const InterpreterOptions &opts, InterpreterHandler *ie, SolverFactory *solver_factory,
             llvm::LLVMContext &context);
    virtual ~Executor();

    const InterpreterHandler &getHandler() {
        return *interpreterHandler;
    }

    virtual bool merge(ExecutionState &base, ExecutionState &other);

    // remove state from queue and delete
    virtual void terminateState(ExecutionState &state);

    // call exit handler and terminate state
    virtual void terminateStateEarly(ExecutionState &state, const llvm::Twine &message);
    // call exit handler and terminate state
    void terminateStateOnExit(ExecutionState &state);
    // call error handler and terminate state
    void terminateStateOnError(ExecutionState &state, const llvm::Twine &message, const char *suffix,
                               const llvm::Twine &longMessage = "");

    // call error handler and terminate state, for execution errors
    // (things that should not be possible, like illegal instruction or
    // unlowered instrinsic, or are unsupported, like inline assembly)
    void terminateStateOnExecError(ExecutionState &state, const llvm::Twine &message, const llvm::Twine &info = "") {
        terminateStateOnError(state, message, "exec.err", info);
    }

    // XXX should just be moved out to utility module
    ref<klee::ConstantExpr> evalConstant(llvm::Constant *c);

    /// Return a unique constant value for the given expression in the
    /// given state, if it has one (i.e. it provably only has a single
    /// value). Otherwise return the original expression.
    ref<Expr> toUnique(const ExecutionState &state, ref<Expr> &e);

    /// Return a constant value for the given expression, forcing it to
    /// be constant in the given state but WITHOUT adding constraints.
    /// Note that this function could break correctness !
    ref<klee::ConstantExpr> toConstantSilent(ExecutionState &state, ref<Expr> e);

    /// Return a constant value for the given expression, forcing it to
    /// be constant in the given state by adding a constraint if
    /// necessary. Note that this function breaks completeness and
    /// should generally be avoided.
    ///
    /// \param purpose An identify string to printed in case of concretization.
    ref<klee::ConstantExpr> toConstant(ExecutionState &state, ref<Expr> e, const char *purpose);

    virtual const llvm::Module *setModule(llvm::Module *module, const ModuleOptions &opts,
                                          bool createStatsTracker = true);

    // Given a concrete object in our [klee's] address space, add it to
    // objects checked code can reference.
    MemoryObject *addExternalObject(ExecutionState &state, void *addr, unsigned size, bool isReadOnly,
                                    bool isUserSpecified = false, bool isSharedConcrete = false,
                                    bool isValueIgnored = false);

    /*** State accessor methods ***/
    virtual bool getSymbolicSolution(TimingSolver *solver,
                                     const std::vector<std::pair<const MemoryObject *, const Array *>> &symbolics,
                                     const ConstraintManager &constraints,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res,
                                     double &queryCost);
    virtual bool getSymbolicSolution(const std::vector<std::pair<const MemoryObject *, const Array *>> &symbolics,
                                     const Assignment &concolics,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res);
    virtual bool getSymbolicSolution(const ExecutionState &state,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res);

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

    TimingSolver *getTimingSolver(const ExecutionState &state) const;
    Solver *getSolver(const ExecutionState &state) const;

    void initializeSolver();

    Expr::Width getWidthForLLVMType(llvm::Type *type) const;

    void printStack(const ExecutionState &state, KInstruction *target, std::stringstream &msg);
};

} // End klee namespace

#endif
