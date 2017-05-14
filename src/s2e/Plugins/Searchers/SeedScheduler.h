///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_SeedScheduler_H
#define S2E_PLUGINS_SeedScheduler_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.h>
#include <s2e/S2EExecutionState.h>

#include "SeedSearcher.h"

namespace s2e {
namespace plugins {
namespace seeds {

enum ExplorationState {
    /*
     * Let S2E find crashes in the first seconds before trying
     * to use any seeds.
     */
    WARM_UP,

    /* Wait for new seeds to become available */
    WAIT_FOR_NEW_SEEDS,

    /* Wait for the guest to actually fetch the seed */
    WAIT_SEED_SCHEDULING,

    /* Wait for a while that the seeds executes */
    WAIT_SEED_EXECUTION
};

class SeedScheduler : public Plugin {
    S2E_PLUGIN
public:
    SeedScheduler(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    SeedSearcher *m_seeds;

    uint64_t m_stateMachineTimeout;
    unsigned m_lowPrioritySeedThreshold;

    ExplorationState m_explorationState;
    uint64_t m_timeOfLastCoveredBlock;
    uint64_t m_timeOfLastCrash;
    uint64_t m_timeOfLastHighPrioritySeed;
    uint64_t m_timeOfLastFetchedSeed;

    void onSeed(const Seed &seed, SeedEvent event);
    void onNewBlockCovered(S2EExecutionState *state);
    void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t address);
    void onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc);
    void onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc);

    void onTimer();

    void processSeedStateMachine(uint64_t currentTime);
};

} // namespace seeds
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SeedScheduler_H
