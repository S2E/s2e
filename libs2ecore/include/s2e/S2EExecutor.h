///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_EXECUTOR_H
#define S2E_EXECUTOR_H

#include <unordered_map>

#include <klee/Executor.h>
#include <llvm/Support/raw_ostream.h>
#include <s2e/s2e_libcpu.h>
#include <timer.h>

#include "S2ETranslationBlock.h"

struct TranslationBlock;
struct CPUX86State;
class TCGLLVMTranslator;

namespace klee {
struct Query;
}

namespace s2e {

class S2E;
class S2EExecutionState;
struct S2ETranslationBlock;

class CpuExitException {};

typedef void (*StateManagerCb)(S2EExecutionState *s, bool killingState);

class S2EExecutor : public klee::Executor {
protected:
    S2E *m_s2e;
    TCGLLVMTranslator *m_llvmTranslator;

    klee::KFunction *m_dummyMain;

    std::vector<klee::ObjectKey> m_saveOnContextSwitch;

    std::vector<S2EExecutionState *> m_deletedStates;

    bool m_executeAlwaysKlee;

    bool m_forkProcTerminateCurrentState;

    bool m_inLoadBalancing;

    struct CPUTimer *m_stateSwitchTimer;

    // This is a set of TBs that are currently stored in libcpu's TB cache
    std::unordered_set<S2ETranslationBlockPtr, S2ETranslationBlockHash, S2ETranslationBlockEqual> m_s2eTbs;

public:
    S2EExecutor(S2E *s2e, TCGLLVMTranslator *translator);
    virtual ~S2EExecutor();

    /** Called on fork, used to trace forks */
    StatePair fork(klee::ExecutionState &current, const klee::ref<klee::Expr> &condition,
                   bool keepConditionTrueInCurrentState = false);

    // A special version of fork() which does not take any symbolic condition,
    // so internally it will just work like the regular fork method
    // except that no path constraints will be added.
    //
    // This method is useful when the user wants to explicitly clone a state
    // in their plugin code and switch back to the cloned state later.
    // Note that `current` state must be running in symbolic mode before it is
    // passed to this method. To make sure your state is running in symbolic mode,
    // do this before calling Executor::fork().
    // ```
    // if (state->needToJumpToSymbolic()) {
    //     state->jumpToSymbolic();
    // }
    // ```
    StatePair fork(klee::ExecutionState &current);

    void flushTb();

    /** Create initial execution state */
    S2EExecutionState *createInitialState();

    void initializeExecution(S2EExecutionState *initialState, bool executeAlwaysKlee);

    void registerCpu(S2EExecutionState *initialState, CPUX86State *cpuEnv);
    void registerRam(S2EExecutionState *initialState, struct MemoryDesc *region, uint64_t startAddress, uint64_t size,
                     uint64_t hostAddress, bool isSharedConcrete, bool saveOnContextSwitch = true,
                     const char *name = "");

    void registerSharedExternalObject(S2EExecutionState *state, void *address, unsigned size);

    void registerDirtyMask(S2EExecutionState *initial_state, uint64_t host_address, uint64_t size);

    void updateConcreteFastPath(S2EExecutionState *state);

    /* Execute llvm function in current context */
    klee::ref<klee::Expr>
    executeFunction(S2EExecutionState *state, llvm::Function *function,
                    const std::vector<klee::ref<klee::Expr>> &args = std::vector<klee::ref<klee::Expr>>());

    klee::ref<klee::Expr>
    executeFunction(S2EExecutionState *state, const std::string &functionName,
                    const std::vector<klee::ref<klee::Expr>> &args = std::vector<klee::ref<klee::Expr>>());

    uintptr_t executeTranslationBlock(S2EExecutionState *state, TranslationBlock *tb);

    static uintptr_t executeTranslationBlockSlow(struct CPUX86State *env1, struct TranslationBlock *tb);
    static uintptr_t executeTranslationBlockFast(struct CPUX86State *env1, struct TranslationBlock *tb);

    /* Returns true if the CPU loop must be exited */
    bool finalizeTranslationBlockExec(S2EExecutionState *state);

    void cleanupTranslationBlock(S2EExecutionState *state);

    S2EExecutionState *selectNextState(S2EExecutionState *state);
    klee::ExecutionState *selectSearcherState(S2EExecutionState *state);

    void updateStates(klee::ExecutionState *current);

    void setCCOpEflags(S2EExecutionState *state);
    void doInterrupt(S2EExecutionState *state, int intno, int is_int, int error_code, uint64_t next_eip, int is_hw);

    static void doInterruptAll(int intno, int is_int, int error_code, uintptr_t next_eip, int is_hw);

    /** Suspend the given state (does not kill it) */
    bool suspendState(S2EExecutionState *state);

    /** Puts back the previously suspended state in the queue */
    bool resumeState(S2EExecutionState *state);

    klee::Searcher *getSearcher() const {
        return searcher;
    }

    void setSearcher(klee::Searcher *s) {
        searcher = s;
    }

    StatePair forkCondition(S2EExecutionState *state, klee::ref<klee::Expr> condition,
                            bool keepConditionTrueInCurrentState = false);

    std::vector<klee::ExecutionState *> forkValues(S2EExecutionState *state, bool isSeedState,
                                                   klee::ref<klee::Expr> expr,
                                                   const std::vector<klee::ref<klee::Expr>> &values);

    bool merge(klee::ExecutionState &base, klee::ExecutionState &other);

    S2ETranslationBlock *allocateS2ETb();
    void flushS2ETBs();

    bool isLoadBalancing() const {
        return m_inLoadBalancing;
    }

    /** Kills the specified state and raises an exception to exit the cpu loop */
    virtual void terminateState(klee::ExecutionState &state);

    /** Kills the specified state and raises an exception to exit the cpu loop */
    virtual void terminateState(klee::ExecutionState &state, const std::string &message);

    void resetStateSwitchTimer();

    // Should be public because of manual forks in plugins
    void notifyFork(klee::ExecutionState &originalState, klee::ref<klee::Expr> &condition, StatePair &targets);

    /**
     * To be called by plugin code
     */
    klee::Executor::StatePair forkAndConcretize(S2EExecutionState *state, klee::ref<klee::Expr> &value_);

protected:
    void updateClockScaling();

    void prepareFunctionExecution(S2EExecutionState *state, llvm::Function *function,
                                  const std::vector<klee::ref<klee::Expr>> &args);
    bool executeInstructions(S2EExecutionState *state, unsigned callerStackSize = 1);

    uintptr_t executeTranslationBlockKlee(S2EExecutionState *state, TranslationBlock *tb);

    uintptr_t executeTranslationBlockConcrete(S2EExecutionState *state, TranslationBlock *tb);

    void deleteState(klee::ExecutionState *state);

    void doStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState);

    void splitStates(const std::vector<S2EExecutionState *> &allStates, klee::StateSet &parentSet,
                     klee::StateSet &childSet);
    void computeNewStateGuids(std::unordered_map<klee::ExecutionState *, uint64_t> &newIds, klee::StateSet &parentSet,
                              klee::StateSet &childSet);

    void doLoadBalancing();

    void notifyBranch(klee::ExecutionState &state);

    void initializeStateSwitchTimer();
    static void stateSwitchTimerCallback(void *opaque);

    void registerFunctionHandlers(llvm::Module &module);

    void replaceExternalFunctionsWithSpecialHandlers();
    void disableConcreteLLVMHelpers();

private:
    // If `condition` is a nullptr, then no path constraints will be added.
    StatePair doFork(klee::ExecutionState &current, const klee::ref<klee::Expr> &condition,
                     bool keepConditionTrueInCurrentState);
};

} // namespace s2e

#endif // S2E_EXECUTOR_H
