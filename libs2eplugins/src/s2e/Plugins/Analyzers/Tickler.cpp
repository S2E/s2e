///
/// Copyright (C) 2020, Vitaly Chipounov
/// Copyright (C) 2014-2020, Cyberhaven
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

#include <qapi/qmp/qstring.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Analyzers/CFIChecker.h>
#include <s2e/Plugins/ExecutionTracers/UserSpaceTracer.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.h>
#include <s2e/Plugins/Support/Screenshot.h>
#include <s2e/S2E.h>

#include "Tickler.h"

namespace s2e {
namespace plugins {

static const float MOVING_AVERAGE_ALPHA = 0.4f;
static const int MIN_TIMER_TICKS = 200;
static const int TIMER_TICK_GRANULARITY = 5;
static const int IDLE_JIT_CODE_CALL_COUNT_AVERAGE = 10;

namespace {

class TicklerState : public PluginState {
public:
    uint64_t m_JITCallCount;
    uint64_t m_JITCallCountPrev;
    uint64_t m_JITCallCountAverage;

    uint64_t m_callCount;

    S2E_TICKLER_CPU_USAGE m_averageCpuUsage;
    unsigned m_cpuUsageIterations;
    unsigned m_autoscrollDoneCount;
    int m_mainWindowOpen;
    bool m_ticklerStarted;

public:
    TicklerState() {
        m_JITCallCount = 0;
        m_JITCallCountPrev = 0;
        m_JITCallCountAverage = 0;
        m_callCount = 0;
        m_averageCpuUsage = {0, 0};
        m_cpuUsageIterations = 0;
        m_autoscrollDoneCount = 0;
        m_mainWindowOpen = 0;
        m_ticklerStarted = false;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new TicklerState();
    }

    virtual ~TicklerState() {
        // Destroy any object if needed
    }

    virtual TicklerState *clone() const {
        return new TicklerState(*this);
    }
};

} // namespace

S2E_DEFINE_PLUGIN(Tickler, "Describe what the plugin does here", "", "MemoryMap", "WindowsMonitor",
                  "ProcessExecutionDetector");

void Tickler::initialize() {
    m_memory = s2e()->getPlugin<MemoryMap>();
    m_monitor = s2e()->getPlugin<WindowsMonitor>();
    m_cfi_checker = s2e()->getPlugin<CFIChecker>();
    m_process = s2e()->getPlugin<ProcessExecutionDetector>();

    auto cfg = s2e()->getConfig();

    m_maxCfiViolations = cfg->getInt(getConfigKey() + ".maxCfiViolations", 0);

    m_generateDumpOnFirstViolation = cfg->getBool(getConfigKey() + ".generateDumpOnFirstViolation");
    m_cpuUsageThreshold = cfg->getInt(getConfigKey() + ".cpuUsageThreshold", 10);
    if (m_cpuUsageThreshold > 100) {
        getWarningsStream() << "Invalid CPU usage threshold\n";
        exit(-1);
    }

    m_heapSprayingThreshold = cfg->getInt(getConfigKey() + ".heapSprayingThreshold", -1);

    // When enabled, waits for the autoscroll done signal to monitor for idle CPU.
    // When disabled, wait for idle CPU after the tickler is loaded.
    m_monitorIdleAfterAutoscroll = cfg->getBool(getConfigKey() + ".monitorIdleAfterAutoscroll", false);

    m_terminateOnJITIdle = cfg->getBool(getConfigKey() + ".terminateOnJITIdle");
    m_timerCount = 0;
    m_timerTicks = 0;
    m_stopRequested = false;

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &Tickler::onTimer));

    if (m_cfi_checker) {
        m_cfi_checker->onCFIViolation.connect(sigc::mem_fun(*this, &Tickler::onCFIViolation));
    }

    m_process->onAllProcessesTerminated.connect(sigc::mem_fun(*this, &Tickler::onAllProcessesTerminated));
}

void Tickler::onAllProcessesTerminated(S2EExecutionState *state) {
    getDebugStream(state) << "Finishing because all tracked processes terminated\n";
    onFYINotification(state, "application terminated unexpectedly");
    stopAnalysis(state);
}

void Tickler::onCFIViolation(S2EExecutionState *state, bool isReturnViolation) {
    // Take a crash dump on first occurence
    WindowsCrashDumpGenerator *dmp = s2e()->getPlugin<WindowsCrashDumpGenerator>();
    if (m_generateDumpOnFirstViolation && dmp) {
        vmi::windows::BugCheckDescription desc;
        dmp->generateManualDump(state, dmp->getPathForDump(state), &desc);
        m_generateDumpOnFirstViolation = false;
    }

    if (!g_s2e_state) {
        return;
    }

    if (!monitor_ready()) {
        return;
    }

    Events::PluginData data;
    // XXX: replace with more informative string coming from the CFIChecker plugin
    QString *str = qstring_from_str("cfi_violation");
    data.push_back(std::make_pair("type", QOBJECT(str)));
    Events::emitQMPEvent(this, data);
}

void Tickler::stopAnalysis(S2EExecutionState *state) {
    auto ss = s2e()->getPlugin<Screenshot>();
    if (ss) {
        getWarningsStream(state) << "taking screenshot before killing state\n";
        ss->takeScreenShot(state);
    }

    Plugin::getWarningsStream(state) << "finishing analysis\n";
    exit(0);
}

void Tickler::stopIfJITCodeNotRunning(S2EExecutionState *state) {

    DECLARE_PLUGINSTATE(TicklerState, state);

    uint64_t delta = plgState->m_JITCallCount - plgState->m_JITCallCountPrev;
    plgState->m_JITCallCountPrev = plgState->m_JITCallCount;

    plgState->m_JITCallCountAverage =
        (uint64_t) ((1 - MOVING_AVERAGE_ALPHA) * plgState->m_JITCallCountAverage + MOVING_AVERAGE_ALPHA * delta);

    if (!m_stopRequested) {
        return;
    }

    Plugin::getDebugStream(state) << "Evaluating JIT activity:"
                                  << " total #calls: " << plgState->m_callCount
                                  << " JIT #calls: " << plgState->m_JITCallCount << " JIT calls delta: " << delta
                                  << " JIT #calls average: " << plgState->m_JITCallCountAverage << "\n";

    if (!m_terminateOnJITIdle) {
        return;
    }

    // wait a few timer ticks before deciding wether to stop
    if ((m_timerTicks++) < MIN_TIMER_TICKS) {
        return;
    }

    if (plgState->m_JITCallCountAverage < IDLE_JIT_CODE_CALL_COUNT_AVERAGE) {

        if (delta > plgState->m_JITCallCountAverage || delta > IDLE_JIT_CODE_CALL_COUNT_AVERAGE) {
            // recent spike in JIT activity, backoff
            m_timerTicks = 0;
            return;
        }

        // almost no JIT-ed code is running, stop the analysis now
        stopAnalysis(state);
    }
}

void Tickler::onTimer(void) {
    static bool highMemoryUsageNotified = false;

    if (m_timerCount < TIMER_TICK_GRANULARITY) {
        ++m_timerCount;
        return;
    }

    m_timerCount = 0;

    if (!g_s2e_state) {
        return;
    }

    uint64_t memUsage = m_memory->getPeakCommitCharge(g_s2e_state);
    if (memUsage >= m_heapSprayingThreshold) {
        if (!highMemoryUsageNotified) {
            onFYINotification(g_s2e_state, "high memory usage");
            highMemoryUsageNotified = true;
        }
    }

    // stopIfJITCodeNotRunning(g_s2e_state);
    if (m_stopRequested) {
        stopAnalysis(g_s2e_state);
    }

    if (m_cfi_checker) {
        stopIfTooManyCFIViolations(g_s2e_state);
        stopIfSegfaultDetected(g_s2e_state);
    }

    stopIfIdle(g_s2e_state);
}

void Tickler::onFYINotification(S2EExecutionState *state, const std::string &info) {
    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    Events::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("fyi"))));
    data.push_back(std::make_pair("info", QOBJECT(qstring_from_str(info.c_str()))));
    Events::emitQMPEvent(this, data);
}

void Tickler::onWindowInfo(S2EExecutionState *state, const std::string &info) {
    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    Events::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("window_text"))));
    data.push_back(std::make_pair("info", QOBJECT(qstring_from_str(info.c_str()))));
    Events::emitQMPEvent(this, data);
}

void Tickler::stopIfTooManyCFIViolations(S2EExecutionState *state) {
    uint64_t faultCount = 0;
    auto &stats = m_cfi_checker->getStats(state);
    faultCount += stats.CallViolationCount;
    faultCount += stats.RetViolationCount;

    if (m_maxCfiViolations) {
        if (faultCount > m_maxCfiViolations) {
            getWarningsStream(state) << "stopping after " << m_maxCfiViolations << " CFI violations\n";
            stopAnalysis(state);
        }
    }
}

void Tickler::stopIfSegfaultDetected(S2EExecutionState *state) {
    static unsigned count = 0;

    uint64_t faultCount = 0;
    auto &stats = m_cfi_checker->getStats(state);
    faultCount += stats.SegFaultCount;
    faultCount += stats.WerFaultCount;

    if (faultCount == 0) {
        return;
    }

    // wait a few timer ticks before deciding whether to stop
    if ((count++) < 2) {
        return;
    }

    getWarningsStream(state) << "got at least one segfault, stopping analysis\n";
    stopAnalysis(state);
}

void Tickler::stopIfIdle(S2EExecutionState *state) {
    static unsigned count = 0;

    DECLARE_PLUGINSTATE(TicklerState, state);

    if (!plgState->m_ticklerStarted) {
        // Tickler may take a long time to load, wait before killing
        getDebugStream(state) << "Guest has not started tickler yet, waiting.\n";
        return;
    }

    if (!plgState->m_mainWindowOpen) {
        // Main window of the tracked app may take a long time to load, wait before killing
        getDebugStream(state) << "Main program window has not been detected yet, waiting.\n";
        return;
    }

    if (m_monitorIdleAfterAutoscroll && !plgState->m_autoscrollDoneCount) {
        // Autoscroll not done yet, don't check for idle
        getDebugStream(state) << "The tickler has not completed document autoscroll yet, waiting.\n";
        return;
    }

    if (plgState->m_averageCpuUsage.ProgramCpuUsage > m_cpuUsageThreshold) {
        // Cpu usage too high, keep waiting
        count = 0;
        getDebugStream(state) << "Program has too high CPU usage (" << plgState->m_averageCpuUsage.ProgramCpuUsage
                              << "%), waiting for it to quiet down...\n";
        return;
    }

    // Some exploits become idle after doing heap spraying, prematurely
    // killing the analysis. This tries to detect cases of high memory
    // usage that could be indicative of heap spraying, and increases the
    // timeout.
    unsigned defaultTimeout = 1; // 20 seconds
    uint64_t memUsage = m_memory->getPeakCommitCharge(state);
    if (memUsage >= m_heapSprayingThreshold) {
        getDebugStream(state) << "Peak commit charge high, suspecting heap spraying, increasing timeout\n";
        defaultTimeout = 20;
    }

    if (m_monitorIdleAfterAutoscroll && plgState->m_autoscrollDoneCount) {
        if (count > defaultTimeout) {
            getDebugStream(state) << "Finishing because idle after autoscroll\n";
            stopAnalysis(state);
            return;
        } else {
            getDebugStream(state) << "Timeout threshold not reached (" << count << "<= " << defaultTimeout << ")\n";
        }
    }

    if (count > std::max<uint64_t>(20, defaultTimeout)) { // 200 secs
        // Sometimes, autoscroll is not properly notified.
        // This catches long idle periods.
        getDebugStream(state) << "Finishing because idle too long\n";
        stopAnalysis(state);
        return;
    }

    ++count;
}

void Tickler::updateAverageCpuUsage(S2EExecutionState *state, const S2E_TICKLER_CPU_USAGE &usage) {

    static const double MOVING_AVERAGE_ALPHA = 0.1;

    DECLARE_PLUGINSTATE(TicklerState, state);

    if (!plgState->m_cpuUsageIterations) {
        plgState->m_averageCpuUsage = usage;
    } else {
        plgState->m_averageCpuUsage.ProgramCpuUsage =
            (1.0 - MOVING_AVERAGE_ALPHA) * (double) plgState->m_averageCpuUsage.ProgramCpuUsage +
            MOVING_AVERAGE_ALPHA * (double) usage.ProgramCpuUsage;
        plgState->m_averageCpuUsage.TotalCpuUsage =
            (1.0 - MOVING_AVERAGE_ALPHA) * (double) plgState->m_averageCpuUsage.TotalCpuUsage +
            MOVING_AVERAGE_ALPHA * (double) usage.TotalCpuUsage;
    }

    ++plgState->m_cpuUsageIterations;

    getDebugStream(state) << "Current CPU Usage: " << usage.ProgramCpuUsage << "% / " << usage.TotalCpuUsage << "%"
                          << " AVG Total: " << (unsigned) plgState->m_averageCpuUsage.TotalCpuUsage << "%"
                          << " AVG Program: " << (unsigned) plgState->m_averageCpuUsage.ProgramCpuUsage << "%"
                          << "\n";
}

void Tickler::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_TICKLER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_TICKLER_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case INIT_DONE: {
            DECLARE_PLUGINSTATE(TicklerState, state);
            getDebugStream(state) << "Init completed\n";
            plgState->m_ticklerStarted = true;
        } break;

        case REPORT_CPU_USAGE:
            updateAverageCpuUsage(state, command.CpuUsage);
            break;

        case AUTOSCROLL_DONE: {
            DECLARE_PLUGINSTATE(TicklerState, state);
            getDebugStream(state) << "Autoscroll done\n";
            ++plgState->m_autoscrollDoneCount;
        } break;

        case MAIN_WINDOW_OPEN: {
            DECLARE_PLUGINSTATE(TicklerState, state);
            getDebugStream(state) << "Main window open\n";
            ++plgState->m_mainWindowOpen = true;
        } break;

        case DONE:
            getWarningsStream(state) << "received DONE command\n";
            m_stopRequested = true;
            break;

        case FYI: {
            std::string info;
            if (state->mem()->readString(command.AsciiZ, info, 2048)) {
                getDebugStream(state) << "received FYI: " << info << "\n";
                onFYINotification(state, info);
            } else {
                getWarningsStream(state) << "could not read FYI info string\n";
            }
        } break;

        case WINDOW_TEXT: {
            std::string info;
            if (state->mem()->readString(command.AsciiZ, info, 4096)) {
                getDebugStream(state) << "received WINDOW_TEXT: " << info << "\n";
                onWindowInfo(state, info);
            } else {
                getWarningsStream(state) << "could not read window text string\n";
            }
        } break;

        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

} // namespace plugins
} // namespace s2e