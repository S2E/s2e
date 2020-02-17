///
/// Copyright (C) 2014, Cyberhaven
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

#ifndef S2E_PLUGINS_ForkLimiter_H
#define S2E_PLUGINS_ForkLimiter_H

#include <llvm/ADT/DenseMap.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class ForkLimiter : public Plugin {
    S2E_PLUGIN
public:
    ForkLimiter(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    typedef llvm::DenseMap<uint64_t, uint64_t> ForkCounts;
    typedef std::map<std::string, ForkCounts> ModuleForkCounts;

    ModuleExecutionDetector *m_detector;
    ModuleForkCounts m_forkCount;

    unsigned m_limit;
    unsigned m_processForkDelay;

    unsigned m_timerTicks;

    void onTimer();
    void onProcessForkDecide(bool *proceed);

    void onStateForkDecide(S2EExecutionState *state, bool *doFork);
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ForkLimiter_H
