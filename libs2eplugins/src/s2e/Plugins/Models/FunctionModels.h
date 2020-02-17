///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
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

class FunctionModels : public BaseFunctionModels, public IPluginInvoker {
    S2E_PLUGIN

public:
    FunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }

    void initialize();

private:
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
