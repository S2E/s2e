///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
