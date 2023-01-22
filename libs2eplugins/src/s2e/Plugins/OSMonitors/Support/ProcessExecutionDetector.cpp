///
/// Copyright (C) 2015-2016, Cyberhaven
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
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ProcessExecutionDetector, "ProcessExecutionDetector S2E plugin", "", "OSMonitor");

class ProcessExecutionDetectorState : public PluginState {
public:
    TrackedPids m_trackedPids;

    // Records whether the plugin has ever seen a configured process
    bool m_hadTrackedProcesses = false;

    bool m_trackKernel = false;

    virtual ProcessExecutionDetectorState *clone() const {
        ProcessExecutionDetectorState *ret = new ProcessExecutionDetectorState(*this);
        return ret;
    }

    bool removePid(uint64_t pid) {
        return m_trackedPids.erase(pid);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ProcessExecutionDetectorState();
    }

    virtual ~ProcessExecutionDetectorState() {
    }
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

    foreach2 (it, moduleList.begin(), moduleList.end()) {
        m_trackedModules.insert(*it);
    }

    m_trackKernel = cfg->getBool(getConfigKey() + ".trackKernel", false);

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
        plgState->m_hadTrackedProcesses = true;
        plgState->m_trackKernel = m_trackKernel;
        onConfigChange.emit(state);
    }
}

void ProcessExecutionDetector::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                               uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);
    if (plgState->removePid(pid)) {
        getDebugStream(state) << "Unloading process " << hexval(pid) << "\n";
        if (plgState->m_hadTrackedProcesses && plgState->m_trackedPids.size() == 0) {
            onAllProcessesTerminated.emit(state);
        }
        onConfigChange.emit(state);
    }
}

bool ProcessExecutionDetector::isTrackingConfigured(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);
    return !plgState->m_trackedPids.empty();
}

bool ProcessExecutionDetector::isTrackedPc(S2EExecutionState *state, uint64_t pc) {
    return isTrackedPc(state, pc, false);
}

bool ProcessExecutionDetector::isTrackedPid(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    if (plgState->m_trackedPids.size() == 0) {
        return false;
    }

    return plgState->m_trackedPids.count(pid) > 0;
}

bool ProcessExecutionDetector::isTrackedModule(const std::string &module) const {
    return m_trackedModules.find(module) != m_trackedModules.end();
}

bool ProcessExecutionDetector::isTrackedPc(S2EExecutionState *state, uint64_t pc, bool checkCpl) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    if (plgState->m_trackedPids.size() == 0) {
        return false;
    }

    if (!plgState->m_trackKernel && m_monitor->isKernelAddress(pc)) {
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

    uint64_t pid = m_monitor->getPid(state);

    return plgState->m_trackedPids.count(pid) > 0;
}

void ProcessExecutionDetector::trackPid(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    getDebugStream(state) << "starting to track pid: " << hexval(pid) << "\n";
    plgState->m_trackedPids.insert(pid);
}

void ProcessExecutionDetector::onMonitorLoadCb(S2EExecutionState *state) {
    onMonitorLoad.emit(state);
}

const TrackedPids &ProcessExecutionDetector::getTrackedPids(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);
    return plgState->m_trackedPids;
}

void ProcessExecutionDetector::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                      uint64_t guestDataSize) {
    DECLARE_PLUGINSTATE(ProcessExecutionDetectorState, state);

    S2E_PROCEXECDETECTOR_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_PROCEXECDETECTOR_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case PROCEXEC_ENABLE_PID:
            plgState->m_trackedPids.insert(command.Pid);
            break;

        case PROCEXEC_DISABLE_PID:
            plgState->m_trackedPids.erase(command.Pid);
            break;
    }

    onConfigChange.emit(state);
}

} // namespace plugins
} // namespace s2e
