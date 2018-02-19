///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc = module->ToNativeBase(state->regs()->getPc());

    if (m_forkCount[module->Name][curPc] > m_limit) {
        *doFork = false;
    }
}

void ForkLimiter::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                         const std::vector<klee::ref<klee::Expr>> &newConditions) {
    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc = module->ToNativeBase(state->regs()->getPc());
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
