///
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ProcessExecutionDetector_H
#define S2E_PLUGINS_ProcessExecutionDetector_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class OSMonitor;

class ProcessExecutionDetector : public Plugin {
    S2E_PLUGIN
public:
    ProcessExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isTracked(S2EExecutionState *state);
    bool isTracked(S2EExecutionState *state, uint64_t pid);
    bool isTracked(const std::string &module) const;
    bool isTrackedPc(S2EExecutionState *state, uint64_t pc, bool checkCpl = false);

    void trackPid(S2EExecutionState *state, uint64_t pid);

    sigc::signal<void, S2EExecutionState *> onMonitorLoad;

private:
    typedef std::unordered_set<std::string> StringSet;

    OSMonitor *m_monitor;

    StringSet m_trackedModules;

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onMonitorLoadCb(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ProcessExecutionDetector_H
