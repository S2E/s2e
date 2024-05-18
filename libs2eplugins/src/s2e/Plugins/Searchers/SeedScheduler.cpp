///
/// Copyright (C) 2017, Cyberhaven
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
#include <s2e/Plugins/Coverage/TranslationBlockCoverage.h>
#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "SeedScheduler.h"

namespace s2e {
namespace plugins {
namespace seeds {

S2E_DEFINE_PLUGIN(SeedScheduler, "Coordinates seed scheduling", "", "SeedSearcher", "OSMonitor",
                  "TranslationBlockCoverage");

void SeedScheduler::initialize() {
    auto now = std::chrono::steady_clock::now();
    m_timeOfLastCoveredBlock = now;
    m_timeOfLastCrash = now;
    m_timeOfLastHighPrioritySeed = now;
    m_timeOfLastFetchedSeed = now;
    m_explorationState = WARM_UP;

    m_seeds = s2e()->getPlugin<SeedSearcher>();
    m_seeds->onSeed.connect(sigc::mem_fun(*this, &SeedScheduler::onSeed));

    coverage::TranslationBlockCoverage *tbcov = s2e()->getPlugin<coverage::TranslationBlockCoverage>();
    tbcov->onNewBlockCovered.connect(sigc::mem_fun(*this, &SeedScheduler::onNewBlockCovered));

    OSMonitor *monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    if (auto lm = dynamic_cast<LinuxMonitor *>(monitor)) {
        lm->onSegFault.connect(sigc::mem_fun(*this, &SeedScheduler::onSegFault));
    } else if (dynamic_cast<WindowsMonitor *>(monitor)) {
        WindowsCrashMonitor *cmon = s2e()->getPlugin<WindowsCrashMonitor>();
        if (!cmon) {
            getWarningsStream() << "Please enable WindowsCrashMonitor to use SeedScheduler with Windows\n";
            exit(-1);
        }
        cmon->onUserModeCrash.connect(sigc::mem_fun(*this, &SeedScheduler::onWindowsUserCrash));
        cmon->onKernelModeCrash.connect(sigc::mem_fun(*this, &SeedScheduler::onWindowsKernelCrash));
    } else {
        getWarningsStream() << "Unsupported OS monitor detected\n";
        exit(-1);
    }

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &SeedScheduler::onTimer),
                                            fsigc::signal_base::HIGH_PRIORITY);

    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &SeedScheduler::onStateKill));
    m_stateKilled = false;

    s2e()->getCorePlugin()->onProcessForkDecide.connect(sigc::mem_fun(*this, &SeedScheduler::onProcessForkDecide));

    ConfigFile *cfg = s2e()->getConfig();

    // How long do we wait before using new seeds.
    //
    // Using seeds is currently expensive. For simple CBs, seeds
    // slow down vulnerability finding by a lot. Use them only when
    // S2E is stuck.
    m_stateMachineTimeout = std::chrono::seconds(cfg->getInt(getConfigKey() + ".stateMachineTimeout", 60));

    // Seeds with priority equal to or lower than the threshold are considered low priority
    // For CFE, high priorities range from 10 to 7 (various types of POVs and crashes),
    // while normal test cases are from 6 and below.
    bool ok = false;
    m_lowPrioritySeedThreshold = cfg->getInt(getConfigKey() + ".lowPrioritySeedThreshold", 6, &ok);
    if (!ok) {
        getWarningsStream() << "lowPrioritySeedThreshold must be set\n";
        exit(-1);
    }
}

///
/// \brief This function prevents needless forking of new instances
/// when there are no available seeds.
///
/// In seed mode, each S2E instance has a copy of state 0, which is
/// scheduled when a new seed is available. This state never gets
/// killed and as a result there are usually at least two states on
/// each S2E instance: the seed fetcher and one or more states that
/// actually execute the seeds.
///
/// The problem is that S2E's load balancer
/// kicks in as soon as there are more than two states availble, in order
/// to spread them across free CPU cores. This will cause an instance fork.
/// In normal circumstances, this is fine. However, if there are not
/// enough seeds available to keep the new instances busy, they will just
/// contain an idle seed fetching state (which will get killed quickly
/// by the idle instance detection mechanism).
///
/// So, in order to prevent excessive instance forking, we use
/// the following algorithm:
///
/// 1. The state with the lowest id gets to decide when to fork a
/// new instance. All other instances just prevent instance forking
/// if there are less than 2 states available.
///
/// 2. The deciding instance forks a new state when there are seeds
/// available and all other nodes are busy. It uses a heuristic for
/// that for now to keep it simple.
///
/// \param proceed is set to false in case the method wants to prevent
/// forking. It is never set to true as this is the default.
///
void SeedScheduler::onProcessForkDecide(bool *proceed) {
    static unsigned previousAvailableSeedCount = 0;
    static time_point lastSeedFetchTime;

    if (s2e()->getExecutor()->getStatesCount() >= 3) {
        // We have plenty of states to load balance, so no need
        // to block instance forking.
        return;
    }

    bool isLeader = s2e()->getCurrentInstanceIndex() == s2e()->getInstanceIndexWithLowestId();
    if (!isLeader) {
        // Only the leader gets to fork new processes, this avoids
        // complex synchronization.
        *proceed = false;
        s2e()->getDebugStream() << "Preventing instance fork because we are not the leader\n";
        return;
    }

    SeedStats stats;
    m_seeds->getSeedStats(stats);

    unsigned idleIdx;
    if (stats.getLowestIdleInstanceIndex(idleIdx)) {
        // Some instances are doing nothing, no point in forking a new one
        *proceed = false;
        s2e()->getDebugStream() << "Preventing instance fork because there are idle instances\n";
        return;
    }

    Seed s;
    if (!m_seeds->getTopPrioritySeed(s)) {
        // There are no more seeds left, don't fork
        s2e()->getDebugStream() << "Preventing instance fork because there are no more seeds\n";
        *proceed = false;
        return;
    }

    // There are seeds left
    auto curTime = std::chrono::steady_clock::now();
    unsigned currentAvailableSeedCount = m_seeds->getSeedCount();
    if (previousAvailableSeedCount > currentAvailableSeedCount) {
        // The number of available seeds has decreased, which means
        // that some worker picked up one of them.
        lastSeedFetchTime = curTime;
    }
    previousAvailableSeedCount = currentAvailableSeedCount;

    auto lastSeedFetchElapsed = curTime - lastSeedFetchTime;

    // The 10 seconds delay allows to workaround busy workers.
    // Ideally, workers should be fast enough to process seeds as they come,
    // but they may often be busy with other tasks and will ignore the
    // new seeds. In this case, we have to spawn new instances if possible,
    // after waiting for a while.
    // TODO: figure out an algorithm that knows exactly which instances
    // won't fetch a seed for a long time, so that there is no need for
    // magic timeout.
    if (lastSeedFetchElapsed < std::chrono::seconds(10) &&
        (s2e()->getCurrentInstanceCount() > currentAvailableSeedCount)) {
        s2e()->getDebugStream() << "Preventing instance fork because there are enough workers\n"
                                << "instanceCnt=" << s2e()->getCurrentInstanceCount()
                                << " availSeeds=" << currentAvailableSeedCount << "\n";
        *proceed = false;
        return;
    }
}

void SeedScheduler::onStateKill(S2EExecutionState *state) {
    m_stateKilled = true;
}

void SeedScheduler::onSeed(const seeds::Seed &seed, seeds::SeedEvent event) {
    if (event == seeds::TERMINATED) {
        getDebugStream() << "Guest terminated seed " << seed.filename << "\n";
        return;
    } else if (event == seeds::SCHEDULING_FAILED) {
        assert(m_explorationState == WAIT_SEED_SCHEDULING);
        m_explorationState = WAIT_FOR_NEW_SEEDS;
        return;
    }

    if (event != seeds::FETCHED) {
        return;
    }

    getDebugStream() << "Guest fetched seed " << seed.filename << "\n";
    getDebugStream() << "Constraints size: " << g_s2e_state->constraints().size() << "\n";

    assert(m_explorationState == WAIT_SEED_SCHEDULING);

    m_explorationState = WAIT_SEED_EXECUTION;
    m_seeds->enableSeeds(false);

    auto now = std::chrono::steady_clock::now();

    m_timeOfLastFetchedSeed = now;

    if (seed.priority > 0) {
        m_timeOfLastHighPrioritySeed = now;
    }
}

void SeedScheduler::onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data) {
    m_timeOfLastCrash = std::chrono::steady_clock::now();
}

void SeedScheduler::onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc) {
    m_timeOfLastCrash = std::chrono::steady_clock::now();
}

void SeedScheduler::onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc) {
    m_timeOfLastCrash = std::chrono::steady_clock::now();
}

void SeedScheduler::onNewBlockCovered(S2EExecutionState *state) {
    m_timeOfLastCoveredBlock = std::chrono::steady_clock::now();
}

void SeedScheduler::terminateIdleInstance() {
    if (s2e()->getExecutor()->getStatesCount() > 1) {
        getDebugStream() << "idle detection: too many states\n";
        return;
    }

    if (s2e()->getCurrentInstanceCount() == 1) {
        // We are the only S2E instance running, don't kill ourselves
        getDebugStream() << "idle detection: single instance\n";
        return;
    }

    SeedStats stats;
    m_seeds->getSeedStats(stats);

    unsigned index;
    if (!stats.getLowestIdleInstanceIndex(index)) {
        // Every S2E instance has seeds to run, return
        getDebugStream() << "idle detection: every instance has seeds\n";
        return;
    }

    if (index != s2e()->getCurrentInstanceIndex()) {
        // We are not the lowest instance
        getDebugStream() << "idle detection: we are not the lowest instance index (" << s2e()->getCurrentInstanceIndex()
                         << ") "
                         << " without seeds (" << index << ")\n";
        return;
    }

    // This is a simple way to synchronize instances in order
    // to avoid multiple instances killing themselves at the
    // same time. Only the instance with the lowest index is
    // allowed to terminate. This means that if there are several
    // idle instances, they will terminate in turn.
    getInfoStream() << "Terminating idle S2E instance\n";
    exit(0);
}

void SeedScheduler::processSeedStateMachine(time_point currentTime) {
    /* Only works for instances that have state 0 */
    if (!m_seeds->isAvailable()) {
        return;
    }

    /* Compute time delta since last major events */
    auto foundBlocksD = currentTime - m_timeOfLastCoveredBlock;
    auto foundCrashesD = currentTime - m_timeOfLastCrash;
    auto recentHighPrioritySeedD = currentTime - m_timeOfLastHighPrioritySeed;
    auto timeOfLastFetchedSeedD = currentTime - m_timeOfLastFetchedSeed;

    bool foundBlocks = foundBlocksD < m_stateMachineTimeout;
    bool foundCrashes = foundCrashesD < m_stateMachineTimeout;
    bool recentHighPrioritySeed = recentHighPrioritySeedD < m_stateMachineTimeout;
    bool recentSeedFetch = timeOfLastFetchedSeedD < m_stateMachineTimeout;

    using namespace std::chrono;
    getInfoStream() << "explorationState: " << m_explorationState << " "
                    << "timeOfLastFetchedSeed: " << duration_cast<seconds>(timeOfLastFetchedSeedD).count() << " "
                    << "foundBlocks: " << duration_cast<seconds>(foundBlocksD).count() << "s "
                    << "foundCrashes: " << duration_cast<seconds>(foundCrashesD).count() << "s "
                    << "hpSeed: " << duration_cast<seconds>(recentHighPrioritySeedD).count() << "s\n";

    if (m_explorationState == WARM_UP) {
        // The warm up phase allows S2E to quickly find crashes and POVS
        // in easy CBs, without incurring overhead of fetching
        // and running the seeds. How long the plugin stays in this phase
        // depends on S2E's success in finding new basic blocks and crashes.
        if (!foundBlocks && !foundCrashes) {
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        } else if ((m_stateKilled || s2e()->getCurrentInstanceCount() > 1) &&
                   (s2e()->getExecutor()->getStatesCount() == 1)) {
            // The warm up phase terminates if no seedless states remain, i.e., there
            // is only state 0 remaining, in which case we have to wait for new seeds
            // as there is nothing else to do. We have to check for m_stateKilled because
            // otherwise we'd always skip the warm up phase (as there is always only one
            // state when S2E starts).
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        } else {
            m_seeds->enableSeeds(false);
        }

    } else if (m_explorationState == WAIT_FOR_NEW_SEEDS) {
        seeds::Seed seed;
        bool hasSeeds = m_seeds->getTopPrioritySeed(seed);
        if (hasSeeds && seed.priority > m_lowPrioritySeedThreshold && !recentHighPrioritySeed) {
            /* Prioritize crash seeds first */
            m_seeds->enableSeeds(true);
            m_explorationState = WAIT_SEED_SCHEDULING;

        } else if (!foundBlocks && !foundCrashes && m_seeds->getSeedCount()) {
            /* Prioritize normal seeds if S2E couldn't find coverage on its own */
            m_seeds->enableSeeds(true);
            m_explorationState = WAIT_SEED_SCHEDULING;
        } else if (s2e()->getExecutor()->getStatesCount() == 1) {
            /* Prioritize normal seeds if no other states are running */
            m_seeds->enableSeeds(true);
            m_explorationState = WAIT_SEED_SCHEDULING;
        } else {
            /* Otherwise, disable seed scheduling to avoid overloading */
            m_seeds->enableSeeds(false);
        }

    } else if (m_explorationState == WAIT_SEED_EXECUTION) {
        /* Give newly fetched seed some time to execute */
        if (!recentSeedFetch || (s2e()->getExecutor()->getStatesCount() == 1)) {
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        }
    }
}

void SeedScheduler::onTimer() {
    // TODO: this should really be a parameter of the onTimer signal
    auto curTime = std::chrono::steady_clock::now();

    // Update the state machine ~ every second
    processSeedStateMachine(curTime);

    terminateIdleInstance();
}

} // namespace seeds
} // namespace plugins
} // namespace s2e
