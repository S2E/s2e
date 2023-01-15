///
/// Copyright (C) 2023, Vitaly Chipounov
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

#include <unordered_set>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/Support/PidTid.h>
#include <s2e/Plugins/OSMonitors/Support/ThreadExecutionDetector.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ThreadExecutionDetector, "ThreadExecutionDetector S2E plugin", "", "OSMonitor");

class ThreadExecutionDetectorState : public PluginState {
public:
    using TrackedPidsTids = std::unordered_set<PidTid>;

    TrackedPidsTids m_trackedPidsTids;

    bool m_trackKernel = false;

    bool m_tracked = false;

    virtual ThreadExecutionDetectorState *clone() const {
        return new ThreadExecutionDetectorState(*this);
    }

    void addPidTid(uint64_t pid, uint64_t tid) {
        m_trackedPidsTids.insert(PidTid(pid, tid));
    }

    bool removePid(uint64_t pid) {
        std::vector<PidTid> toErase;
        for (const auto &pt : m_trackedPidsTids) {
            if (pt.first == pid) {
                toErase.push_back(pt);
            }
        }

        for (const auto &pt : toErase) {
            m_trackedPidsTids.erase(pt);
        }

        return toErase.size() > 0;
    }

    void removePidTid(uint64_t pid, uint64_t tid) {
        m_trackedPidsTids.erase(PidTid(pid, tid));
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ThreadExecutionDetectorState();
    }

    virtual ~ThreadExecutionDetectorState() {
    }
};

void ThreadExecutionDetector::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ThreadExecutionDetector::onProcessUnload));
}

void ThreadExecutionDetector::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(ThreadExecutionDetectorState, state);
    plgState->removePidTid(thread.Pid, thread.Tid);
}

void ThreadExecutionDetector::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                              uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ThreadExecutionDetectorState, state);
    plgState->removePid(pid);
}

bool ThreadExecutionDetector::isTrackingConfigured(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ThreadExecutionDetectorState, state);
    return !plgState->m_trackedPidsTids.empty();
}

bool ThreadExecutionDetector::isTrackedPc(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ThreadExecutionDetectorState, state);

    // Ignore 16-bit mode.
    if ((env->hflags >> HF_VM_SHIFT) & 1) {
        return false;
    }

    auto hasPidsTids = plgState->m_trackedPidsTids.size() > 0;
    if (!hasPidsTids) {
        return false;
    }

    if (!plgState->m_trackKernel && m_monitor->isKernelAddress(pc)) {
        return false;
    }

    auto pid = m_monitor->getPid(state);
    auto tid = m_monitor->getTid(state);

    auto tracked_thread = plgState->m_trackedPidsTids.count(PidTid(pid, tid)) > 0;

    return tracked_thread;
}

void ThreadExecutionDetector::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                     uint64_t guestDataSize) {
    DECLARE_PLUGINSTATE(ThreadExecutionDetectorState, state);

    S2E_THREADEXECDETECTOR_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_THREADEXECDETECTOR_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case THREADEXEC_ENABLE_KERNEL_TRACKING:
            plgState->m_trackKernel = true;
            break;

        case THREADEXEC_DISABLE_KERNEL_TRACKING:
            plgState->m_trackKernel = false;
            break;

        case THREADEXEC_ENABLE_CURRENT: {
            auto pid = m_monitor->getPid(state);
            auto tid = m_monitor->getTid(state);
            plgState->addPidTid(pid, tid);
            plgState->m_tracked = true;
        } break;

        case THREADEXEC_DISABLE_CURRENT: {
            auto pid = m_monitor->getPid(state);
            auto tid = m_monitor->getTid(state);
            plgState->removePidTid(pid, tid);
            plgState->m_tracked = false;
        } break;
    }

    onConfigChange.emit(state);
}

} // namespace plugins
} // namespace s2e
