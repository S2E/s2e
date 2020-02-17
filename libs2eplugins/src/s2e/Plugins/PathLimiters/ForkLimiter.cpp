///
/// Copyright (C) 2014-2015, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "ForkLimiter.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ForkLimiter, "Limits how many times each instruction in a module can fork", "");

void ForkLimiter::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &ForkLimiter::onTimer));

    s2e()->getCorePlugin()->onProcessForkDecide.connect(sigc::mem_fun(*this, &ForkLimiter::onProcessForkDecide));

    // Limit of forks per program counter, -1 means don't care
    bool ok;
    m_limit = s2e()->getConfig()->getInt(getConfigKey() + ".maxForkCount", 10, &ok);
    if ((int) m_limit != -1) {
        if (m_detector) {
            s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &ForkLimiter::onStateForkDecide));

            s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &ForkLimiter::onFork));
        } else if (ok) {
            getWarningsStream() << "maxForkCount requires ModuleExecutionDetector\n";
            exit(-1);
        }
    }

    // Wait 5 seconds before allowing an S2E instance to fork
    m_processForkDelay = s2e()->getConfig()->getInt(getConfigKey() + ".processForkDelay", 5);

    m_timerTicks = 0;
}

void ForkLimiter::onStateForkDecide(S2EExecutionState *state, bool *doFork) {
    auto module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc;
    if (!module->ToNativeBase(state->regs()->getPc(), curPc)) {
        getWarningsStream(state) << "Could not get relative pc for module " << module->Name << "\n";
        return;
    }

    if (m_forkCount[module->Name][curPc] > m_limit) {
        *doFork = false;
    }
}

void ForkLimiter::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions) {
    auto module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc;
    if (!module->ToNativeBase(state->regs()->getPc(), curPc)) {
        getWarningsStream(state) << "Could not get relative pc for module " << module->Name << "\n";
        return;
    }
    ++m_forkCount[module->Name][curPc];
}

void ForkLimiter::onProcessForkDecide(bool *proceed) {
    // Rate-limit forking
    if (m_timerTicks < m_processForkDelay) {
        *proceed = false;
        return;
    }

    m_timerTicks = 0;
}

void ForkLimiter::onTimer() {
    ++m_timerTicks;
}

} // namespace plugins
} // namespace s2e
