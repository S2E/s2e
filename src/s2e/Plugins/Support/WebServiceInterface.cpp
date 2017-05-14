///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include "WebServiceInterface.h"

extern "C" {
#include <qbool.h>
#include <qstring.h>
}

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(WebServiceInterface, "WebServiceInterface S2E plugin", "", );

void WebServiceInterface::initialize() {
    ConfigFile *cfg = s2e()->getConfig();
    m_statsUpdateInterval = cfg->getInt(getConfigKey() + ".statsUpdateInterval", 10);
    m_statsLastSent = 0;
    m_maxCompletedPathDepth = 0;
    m_maxPathDepth = 0;
    m_completedPaths = 0;
    m_completedSeeds = 0;
    m_segFaults = 0;

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &WebServiceInterface::onEngineShutdown));
    s2e()->getCorePlugin()->onStateKill.connect_front(sigc::mem_fun(*this, &WebServiceInterface::onStateKill));
    s2e()->getCorePlugin()->onTimer.connect_front(sigc::mem_fun(*this, &WebServiceInterface::onTimer));
    s2e()->getCorePlugin()->onProcessForkComplete.connect_front(
        sigc::mem_fun(*this, &WebServiceInterface::onProcessForkComplete));

    m_seedSearcher = s2e()->getPlugin<seeds::SeedSearcher>();
    if (m_seedSearcher) {
        m_seedSearcher->onSeed.connect(sigc::mem_fun(*this, &WebServiceInterface::onSeed));
    } else {
        getWarningsStream() << "SeedSearcher not present, seed statistics will not be available\n";
    }

    m_recipe = s2e()->getPlugin<recipe::Recipe>();
    if (!m_recipe) {
        getWarningsStream() << "Recipe plugin not present, recipe statistics will not be available\n";
    }

    LinuxMonitor *linux = s2e()->getPlugin<LinuxMonitor>();
    WindowsMonitor *windows = s2e()->getPlugin<WindowsMonitor>();

    if (linux) {
        linux->onSegFault.connect(sigc::mem_fun(*this, &WebServiceInterface::onSegFault));
    } else if (windows) {
        WindowsCrashMonitor *crash = s2e()->getPlugin<WindowsCrashMonitor>();
        if (!crash) {
            getWarningsStream() << "Please enable WindowsCrashMonitor to use SeedScheduler with Windows\n";
            exit(-1);
        }
        crash->onUserModeCrash.connect(sigc::mem_fun(*this, &WebServiceInterface::onWindowsUserCrash));
        crash->onKernelModeCrash.connect(sigc::mem_fun(*this, &WebServiceInterface::onWindowsKernelCrash));
    } else {
        getWarningsStream() << "No compatible OS monitor enabled, segfault stats will not be available\n";
    }
}

QDict *WebServiceInterface::getGlobalStats() {
    QDict *stats = qdict_new();

    qdict_put_obj(stats, "instance_current_count", QOBJECT(qint_from_int(s2e()->getCurrentProcessCount())));
    qdict_put_obj(stats, "instance_max_count", QOBJECT(qint_from_int(s2e()->getMaxProcesses())));

    // state_highest_id is the highest state id across all currently running nodes.
    // To obtain number of queued paths, sum all state_completed_count and subtract from highest_state_id.
    qdict_put_obj(stats, "state_highest_id", QOBJECT(qint_from_int(s2e()->fetchNextStateId())));
    qdict_put_obj(stats, "state_completed_count", QOBJECT(qint_from_int(m_completedPaths)));
    m_completedPaths = 0;

    // Number of constraints on the deepest completed path
    qdict_put_obj(stats, "state_max_completed_depth", QOBJECT(qint_from_int(m_maxCompletedPathDepth)));

    // Approximate current maximum path depth
    if (g_s2e_state) {
        uint32_t tmp = std::max(m_maxCompletedPathDepth, (uint32_t) g_s2e_state->constraints.size());
        m_maxPathDepth = std::max(m_maxPathDepth, tmp);
    }

    qdict_put_obj(stats, "state_max_depth", QOBJECT(qint_from_int(m_maxPathDepth)));

    // Number of seed paths that terminated
    qdict_put_obj(stats, "seeds_completed", QOBJECT(qint_from_int(m_completedSeeds)));

    // Fetch the global seed count, the service will display
    // the max count received from all nodes. All nodes should
    // normally have the same value, since it comes from a shared structure.
    if (m_seedSearcher) {
        qdict_put_obj(stats, "seeds_used", QOBJECT(qint_from_int(m_seedSearcher->getUsedSeedsCount(true))));
    }

    if (m_recipe) {
        const recipe::RecipeStats &recipeStats = m_recipe->getStats();
        qdict_put_obj(stats, "recipe_invalid_count", QOBJECT(qint_from_int(recipeStats.invalidRecipeCount)));
        qdict_put_obj(stats, "recipe_failed_tries", QOBJECT(qint_from_int(recipeStats.failedRecipeTries)));
        qdict_put_obj(stats, "recipe_successful_tries", QOBJECT(qint_from_int(recipeStats.successfulRecipeTries)));
        qdict_put_obj(stats, "recipe_count", QOBJECT(qint_from_int(m_recipe->getRecipeCount())));

        // The service will sum all stats, so need to reset here
        m_recipe->resetStats();
    }

    qdict_put_obj(stats, "segfault_count", QOBJECT(qint_from_int(m_segFaults)));
    m_segFaults = 0;

    return stats;
}

void WebServiceInterface::sendStats() {
    Events::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("stats"))));
    data.push_back(std::make_pair("global_stats", QOBJECT(getGlobalStats())));
    Events::emitQMPEvent(this, data);
}

void WebServiceInterface::onTimer() {

    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    // Need to use real time, because onTimer may not be called
    // exactly once per second, and could be delayed for a long
    // time by blocking operations (e.g., constraint solver)

    // TODO: this should really be a parameter of the onTimer signal
    uint64_t curTime = llvm::sys::TimeValue::now().seconds();

    if (curTime - m_statsLastSent < m_statsUpdateInterval) {
        return;
    }

    m_statsLastSent = curTime;

    sendStats();
}

void WebServiceInterface::onEngineShutdown() {
    // Send updated stats before shutting down.
    // onTimer might have been fired a long time ago.
    sendStats();
}

void WebServiceInterface::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    ++m_segFaults;
}

void WebServiceInterface::onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc) {
    ++m_segFaults;
}

void WebServiceInterface::onWindowsKernelCrash(S2EExecutionState *state,
                                               const vmi::windows::BugCheckDescription &desc) {
    ++m_segFaults;
}

void WebServiceInterface::onProcessForkComplete(bool isChild) {
    if (isChild) {
        // These variables have to be reset in the child process
        // because they reflect the stats of the parent process.
        m_completedPaths = 0;
        m_completedSeeds = 0;
        m_segFaults = 0;

        if (m_recipe) {
            m_recipe->resetStats();
        }
    }
}

void WebServiceInterface::onStateKill(S2EExecutionState *state) {
    ++m_completedPaths;
    m_maxCompletedPathDepth = std::max(m_maxCompletedPathDepth, (unsigned) state->constraints.size());
}

void WebServiceInterface::onSeed(const seeds::Seed &seed, seeds::SeedEvent event) {
    if (event == seeds::TERMINATED) {
        getDebugStream() << "Guest terminated seed " << seed.filename << "\n";
        ++m_completedSeeds;
    }
}

} // namespace plugins
} // namespace s2e
