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

class LLVMExecutorException : public std::runtime_error {
public:
    LLVMExecutorException(const std::string &msg) : std::runtime_error(msg) {
    }
};

class Executor {
public:
    typedef std::pair<ExecutionStatePtr, ExecutionStatePtr> StatePair;

protected:
    // ======= LLVM management =======
    KModulePtr m_kmodule;
    /// The set of functions that must be handled via custom function handlers
    /// instead of being called directly.
    std::set<llvm::Function *> m_overridenInternalFunctions;

    /// Map of globals to their bound address. This also includes
    /// globals that have no representative object (i.e. functions).
    GlobalAddresses m_globalAddresses;

    /// Map of globals to their representative memory object.
    std::map<const llvm::GlobalValue *, ObjectKey> m_globalObjects;

    /// Map of predefined global values
    std::map<std::string, void *> m_predefinedSymbols;

    std::unique_ptr<SpecialFunctionHandler> m_specialFunctionHandler;

    // ======= Misc =======

    std::unique_ptr<ExternalDispatcher> m_externalDispatcher;

    // ======= Execution state management =======
    Searcher *m_searcher;
    StateSet m_states;

    void executeInstruction(ExecutionState &state, KInstruction *ki);

    void initializeGlobalObject(ExecutionState &state, const ObjectStatePtr &os, const llvm::Constant *c,
                                unsigned offset);
    void initializeGlobals(ExecutionState &state);

    void callExternalFunction(ExecutionState &state, KInstruction *target, llvm::Function *function,
                              std::vector<ref<Expr>> &arguments);

    void executeCall(ExecutionState &state, KInstruction *ki, llvm::Function *f, std::vector<ref<Expr>> &arguments);

    // do address resolution / object binding / out of bounds checking
    // and perform the operation
    void executeMemoryOperation(ExecutionState &state, bool isWrite, ref<Expr> address,
                                ref<Expr> value /* undef if read */, KInstruction *target /* undef if write */);

    const Cell &eval(KInstruction *ki, unsigned index, LLVMExecutionState &state) const;

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
    virtual StatePair fork(ExecutionState &current, const ref<Expr> &condition, bool keepConditionTrueInCurrentState,
                           std::function<void(ExecutionStatePtr, const StatePair &)> onBeforeNotify) = 0;

    // remove state from queue and delete
    virtual void terminateState(ExecutionStatePtr state);

    virtual const llvm::Module *setModule(llvm::Module *module);

    static void reexecuteCurrentInstructionInForkedState(ExecutionStatePtr state, const StatePair &sp);
    static void skipCurrentInstructionInForkedState(ExecutionStatePtr state, const StatePair &sp);

    const StateSet &states() const {
        return m_states;
    }

    KModulePtr getModule() const {
        return m_kmodule;
    }
};

} // namespace klee

#endif
