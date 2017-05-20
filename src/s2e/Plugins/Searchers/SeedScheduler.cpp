///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    uint64_t now = llvm::sys::TimeValue::now().seconds();
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
    } else if (auto dm = dynamic_cast<DecreeMonitor *>(monitor)) {
        dm->onSegFault.connect(sigc::mem_fun(*this, &SeedScheduler::onSegFault));
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

    s2e()->getCorePlugin()->onTimer.connect_front(sigc::mem_fun(*this, &SeedScheduler::onTimer));

    ConfigFile *cfg = s2e()->getConfig();

    // How long do we wait before using new seeds.
    //
    // Using seeds is currently expensive. For simple CBs, seeds
    // slow down vulnerability finding by a lot. Use them only when
    // S2E is stuck.
    m_stateMachineTimeout = cfg->getInt(getConfigKey() + ".stateMachineTimeout", 60);

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
    getDebugStream() << "Constraints size: " << g_s2e_state->constraints.size() << "\n";

    assert(m_explorationState == WAIT_SEED_SCHEDULING);

    m_explorationState = WAIT_SEED_EXECUTION;
    m_seeds->enableSeeds(false);

    uint64_t now = llvm::sys::TimeValue::now().seconds();

    m_timeOfLastFetchedSeed = now;

    if (seed.priority > 0) {
        m_timeOfLastHighPrioritySeed = now;
    }
}

void SeedScheduler::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t address) {
    m_timeOfLastCrash = llvm::sys::TimeValue::now().seconds();
}

void SeedScheduler::onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc) {
    m_timeOfLastCrash = llvm::sys::TimeValue::now().seconds();
}

void SeedScheduler::onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc) {
    m_timeOfLastCrash = llvm::sys::TimeValue::now().seconds();
}

void SeedScheduler::onNewBlockCovered(S2EExecutionState *state) {
    m_timeOfLastCoveredBlock = llvm::sys::TimeValue::now().seconds();
}

void SeedScheduler::processSeedStateMachine(uint64_t currentTime) {
    /* Only works for instances that have state 0 */
    if (!m_seeds->isAvailable()) {
        return;
    }

    /* Compute time delta since last major events */
    unsigned foundBlocksD = currentTime - m_timeOfLastCoveredBlock;
    unsigned foundCrashesD = currentTime - m_timeOfLastCrash;
    unsigned recentHighPrioritySeedD = currentTime - m_timeOfLastHighPrioritySeed;
    unsigned timeOfLastFetchedSeedD = currentTime - m_timeOfLastFetchedSeed;

    bool foundBlocks = foundBlocksD < m_stateMachineTimeout;
    bool foundCrashes = foundCrashesD < m_stateMachineTimeout;
    bool recentHighPrioritySeed = recentHighPrioritySeedD < m_stateMachineTimeout;
    bool recentSeedFetch = timeOfLastFetchedSeedD < m_stateMachineTimeout;

    getDebugStream() << "explorationState: " << m_explorationState << " "
                     << "timeOfLastFetchedSeed: " << timeOfLastFetchedSeedD << " "
                     << "foundBlocks: " << foundBlocksD << "s "
                     << "foundCrashes: " << foundCrashesD << "s "
                     << "hpSeed: " << recentHighPrioritySeedD << "s\n";

    if (m_explorationState == WARM_UP) {
        /* The warm up phase allows S2E to quickly find crashes and POVS
         * in easy CBs, without incurring overhead of fetching
         * and running the seeds. How long the plugin stays in this phase
         * depends on S2E's success in finding new basic blocks and crashes.*/
        if (!foundBlocks && !foundCrashes) {
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

        } else {
            /* Otherwise, disable seed scheduling to avoid overloading */
            m_seeds->enableSeeds(false);
        }

    } else if (m_explorationState == WAIT_SEED_EXECUTION) {
        /* Give newly fetched seed some time to execute */
        if (!recentSeedFetch) {
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        }
    }
}

void SeedScheduler::onTimer() {
    // TODO: this should really be a parameter of the onTimer signal
    uint64_t curTime = llvm::sys::TimeValue::now().seconds();

    // Update the state machine ~ every second
    processSeedStateMachine(curTime);
}

} // namespace seeds
} // namespace plugins
} // namespace s2e
