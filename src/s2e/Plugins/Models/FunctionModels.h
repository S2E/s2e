///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FUNCTION_MODELS_H
#define S2E_PLUGINS_FUNCTION_MODELS_H

#include <s2e/Plugins/Core/BaseInstructions.h>

#include "BaseFunctionModels.h"

struct S2E_LIBCWRAPPER_COMMAND;

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {
namespace models {

class FunctionModels : public BaseFunctionModels, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN

public:
    FunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }

private:
    virtual klee::ref<klee::Expr> readMemory8(S2EExecutionState *state, uint64_t addr);

    void handleStrlen(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrncmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd);
    void handleStrncpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd);
    void handleMemcpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd);
    void handleMemcmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, klee::ref<klee::Expr> &expr);
    void handleStrcat(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd);
    void handleStrncat(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd);
    void handleCrc(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &ret);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
