///
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <llvm/ADT/DenseSet.h>

#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ProcessExecutionDetector, "ProcessExecutionDetector S2E plugin", "", "OSMonitor");

typedef llvm::DenseSet<uint64_t> TrackedPids;

class ProcessExecutionDetectorState : public PluginState {
public:
    virtual ProcessExecutionDetectorState *clone() const {
        ProcessExecutionDetectorState *ret = new ProcessExecutionDetectorState(*this);
        return ret;
    }

    ProcessExecutionDetectorState() {
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ProcessExecutionDetectorState();
    }

    virtual ~ProcessExecutionDetectorState() {
    }

    TrackedPids m_trackedPids;
};

void ProcessExecutionDetector::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    // Fetch the list of modules where to report the calls
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list moduleList =
        cfg->getStringList(getConfigKey() + ".moduleNames", ConfigFile::string_list(), &ok);

    if (moduleList.empty()) {
        getWarningsStream() << "no modules configured\n";
    }

    foreach2 (it, moduleList.begin(), moduleList.end()) { m_trackedModules.insert(*it); }

    m_monitor->onProcessLoad.connect(sigc::mem_fun(*this, &ProcessExecutionDetector::onProcessLoad));

    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ProcessExecutionDetector::onProcessUnload));

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &ProcessExecutionDetector::onMonitorLoadCb));
}

void ProcessExecutionDetector::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                             const std::string &ImageFileName) {
    if (m_trackedModules.find(ImageFileName) != m_trackedModules.end()) {
        DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

        getDebugStream(state) << "starting to track: " << ImageFileName << " (pid: " << hexval(pid)
                              << " as: " << hexval(pageDir) << ")\n";

        plgState->m_trackedPids.insert(pid);
    }
}

void ProcessExecutionDetector::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                               uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);
    if (plgState->m_trackedPids.erase(pid)) {
        getDebugStream(state) << "Unloading process " << hexval(pid) << "\n";
    }
}

bool ProcessExecutionDetector::isTracked(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    if (plgState->m_trackedPids.size() == 0) {
        return false;
    }

    return plgState->m_trackedPids.count(pid) > 0;
}

bool ProcessExecutionDetector::isTracked(S2EExecutionState *state) {
    return isTrackedPc(state, state->getPc());
}

bool ProcessExecutionDetector::isTrackedPc(S2EExecutionState *state, uint64_t pc, bool checkCpl) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    if (plgState->m_trackedPids.size() == 0) {
        return false;
    }

    if (m_monitor->isKernelAddress(pc)) {
        return false;
    }

    // Ignore 16-bit mode
    if ((env->hflags >> HF_VM_SHIFT) & 1) {
        return false;
    }

    if (checkCpl) {
        /* sometimes, we want to ignore this check, for e.g., right after doing a syscall */
        if ((env->hflags & HF_CPL_MASK) != 3) {
            return false;
        }
    }

    uint64_t pid = m_monitor->getPid(state, state->getPc());

    return plgState->m_trackedPids.count(pid) > 0;
}

void ProcessExecutionDetector::onMonitorLoadCb(S2EExecutionState *state) {
    onMonitorLoad.emit(state);
}

} // namespace plugins
} // namespace s2e
