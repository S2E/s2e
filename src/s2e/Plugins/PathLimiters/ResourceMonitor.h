///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ResourceMonitor_H
#define S2E_PLUGINS_ResourceMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>

#include <memory>

namespace s2e {
namespace plugins {

class ResourceMonitor : public Plugin {
    S2E_PLUGIN
public:
    ResourceMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    uint64_t m_timerCount;
    uint64_t m_rss;
    uint64_t m_cgroupMemLimit;
    std::string m_memStatFileName;
    S2ESynchronizedObject<bool> m_notifiedQMP;

    void onStateForkDecide(S2EExecutionState *state, bool *doFork);
    void onTimer(void);
    void updateMemoryUsage();
    bool memoryLimitExceeded();
    void dropStates();
    void emitQMPNofitication();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ResourceMonitor_H
