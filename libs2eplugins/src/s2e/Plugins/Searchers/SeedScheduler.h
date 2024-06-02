///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_SeedScheduler_H
#define S2E_PLUGINS_SeedScheduler_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
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
    using time_point = std::chrono::steady_clock::time_point;

    SeedSearcher *m_seeds;

    std::chrono::seconds m_stateMachineTimeout;
    unsigned m_lowPrioritySeedThreshold;
    bool m_stateKilled;

    ExplorationState m_explorationState;
    time_point m_timeOfLastCoveredBlock;
    time_point m_timeOfLastCrash;
    time_point m_timeOfLastHighPrioritySeed;
    time_point m_timeOfLastFetchedSeed;

    void onSeed(const Seed &seed, SeedEvent event);
    void onNewBlockCovered(S2EExecutionState *state);
    void onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data);
    void onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc);
    void onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc);

    void onProcessForkDecide(bool *proceed);
    void onTimer();
    void onStateKill(S2EExecutionState *state);

    void processSeedStateMachine(time_point currentTime);

    ///
    /// \brief Terminates an idle S2E instance
    ///
    /// An idle S2E instance is an instance that only has one state running,
    /// and that state waits for new seeds. It may happen that the system
    /// is filled with idle instances. This situation prevents busy instances
    /// to offload some of their states by forking new S2E instances because
    /// all the slots are taken by idle instances. Killing the idle instances
    /// frees up instance slots so that the busy S2E process can fork a child again.
    ///
    /// NOTE: this is required only because S2E has no mechanism to migrate
    /// states between already running instances.
    ///
    void terminateIdleInstance();
};

} // namespace seeds
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SeedScheduler_H
