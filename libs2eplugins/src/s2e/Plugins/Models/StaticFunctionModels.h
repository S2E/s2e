///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#ifndef S2E_PLUGINS_StaticFunctionModels_H
#define S2E_PLUGINS_StaticFunctionModels_H

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <llvm/ADT/StringMap.h>

#include "BaseFunctionModels.h"

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {

class ModuleExecutionDetector;

namespace models {

class StaticFunctionModels : public BaseFunctionModels {
    S2E_PLUGIN

public:
    StaticFunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {
    }

    void initialize();

    ///
    /// \brief Returns how many function models are available.
    ///
    unsigned getFunctionModelCount() const;

private:
    typedef bool (StaticFunctionModels::*OpHandler)(S2EExecutionState *state, uint64_t pc);
    typedef llvm::StringMap<OpHandler> HandlerMap;

    ModuleExecutionDetector *m_detector;
    HandlerMap m_handlers;

    void onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                   TranslationBlock *tb, uint64_t endPc, bool staticTarget, uint64_t targetPc);

    bool getBool(S2EExecutionState *state, const std::string &property);

    bool handleStrlen(S2EExecutionState *state, uint64_t pc);
    bool handleStrcmp(S2EExecutionState *state, uint64_t pc);
    bool handleStrncmp(S2EExecutionState *state, uint64_t pc);
    bool handleStrcpy(S2EExecutionState *state, uint64_t pc);
    bool handleStrncpy(S2EExecutionState *state, uint64_t pc);
    bool handleMemcpy(S2EExecutionState *state, uint64_t pc);
    bool handleMemcmp(S2EExecutionState *state, uint64_t pc);
    bool handleStrcat(S2EExecutionState *state, uint64_t pc);
    bool handleStrncat(S2EExecutionState *state, uint64_t pc);
    bool handleCrc16(S2EExecutionState *state, uint64_t pc);
    bool handleCrc32(S2EExecutionState *state, uint64_t pc);

    void onCall(S2EExecutionState *state, uint64_t pc, OpHandler handler);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
