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

#include <chrono>

namespace s2e {
namespace plugins {

class WebServiceInterface : public Plugin {
    S2E_PLUGIN
public:
    WebServiceInterface(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    using time_point = std::chrono::steady_clock::time_point;
    time_point m_statsLastSent;
    std::chrono::seconds m_statsUpdateInterval;

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
