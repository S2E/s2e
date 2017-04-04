///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_CUSTINST_H

#define S2E_PLUGINS_CUSTINST_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class OSMonitor;

class BaseInstructionsPluginInvokerInterface {
public:
    virtual ~BaseInstructionsPluginInvokerInterface() {
    }
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) = 0;
};

typedef enum S2E_BASEINSTRUCTION_COMMANDS { ALLOW_CURRENT_PID, GET_HOST_CLOCK_MS } S2E_BASEINSTRUCTION_COMMANDS;

typedef struct S2E_BASEINSTRUCTION_COMMAND {
    S2E_BASEINSTRUCTION_COMMANDS Command;
    union {
        uint64_t Milliseconds;
    };
} S2E_BASEINSTRUCTION_COMMAND;

class BaseInstructions : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    BaseInstructions(S2E *s2e) : Plugin(s2e) {
    }
    virtual ~BaseInstructions() {
    }

    void initialize();

    void handleBuiltInOps(S2EExecutionState *state, uint64_t opcode);

    void makeSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size, const std::string &nameStr,
                      bool makeConcolic, std::vector<klee::ref<klee::Expr>> *varData = NULL,
                      std::string *varName = NULL);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    OSMonitor *m_monitor;

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void forkCount(S2EExecutionState *state);
    void allowCurrentPid(S2EExecutionState *state);
    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);
    void checkPlugin(S2EExecutionState *state) const;
    void invokePlugin(S2EExecutionState *state);
    void makeSymbolic(S2EExecutionState *state, bool makeConcolic);
    void isSymbolic(S2EExecutionState *state);
    void killState(S2EExecutionState *state);
    void printExpression(S2EExecutionState *state);
    void printMessage(S2EExecutionState *state, bool isWarning);
    void printMemory(S2EExecutionState *state);
    void hexDump(S2EExecutionState *state);
    void concretize(S2EExecutionState *state, bool addConstraint);
    void sleep(S2EExecutionState *state);
    void assume(S2EExecutionState *state);
    void assumeRange(S2EExecutionState *state);
    void assumeDisjunction(S2EExecutionState *state);
    void assumeInternal(S2EExecutionState *state, klee::ref<klee::Expr> expr);
    void writeBuffer(S2EExecutionState *state);
    void getRange(S2EExecutionState *state);
    void getConstraintsCountForExpression(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif
