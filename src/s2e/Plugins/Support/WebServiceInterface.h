///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_WEBSVC_H
#define S2E_PLUGINS_WEBSVC_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/Events.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>
#include <s2e/Plugins/VulnerabilityAnalysis/Recipe/Recipe.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class WebServiceInterface : public Plugin {
    S2E_PLUGIN
public:
    WebServiceInterface(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    uint64_t m_statsLastSent;
    uint64_t m_statsUpdateInterval;

    uint32_t m_maxCompletedPathDepth;
    uint32_t m_maxPathDepth;

    uint32_t m_completedPaths;
    uint32_t m_completedSeeds;

    uint32_t m_segFaults;

    seeds::SeedSearcher *m_seedSearcher;
    recipe::Recipe *m_recipe;

    void sendStats();

    void onEngineShutdown();
    void onTimer();
    void onProcessForkComplete(bool isChild);
    void onStateKill(S2EExecutionState *state);
    void onSeed(const seeds::Seed &seed, seeds::SeedEvent event);
    void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc);

    void onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc);
    void onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc);

    QDict *getGlobalStats();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_WEBSVC_H
