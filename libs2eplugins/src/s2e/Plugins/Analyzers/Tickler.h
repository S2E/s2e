///
/// Copyright (C) 2020, Vitaly Chipounov
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

#ifndef S2E_PLUGINS_TICKLER_H
#define S2E_PLUGINS_TICKLER_H

#include <s2e/Plugin.h>

#include <s2e/Plugins/Core/BaseInstructions.h>

namespace s2e {
namespace plugins {

class MemoryMap;
class WindowsMonitor;
class CFIChecker;
class ProcessExecutionDetector;

enum S2E_TICKLER_COMMANDS { INIT_DONE, REPORT_CPU_USAGE, AUTOSCROLL_DONE, MAIN_WINDOW_OPEN, DONE, FYI, WINDOW_TEXT };

struct S2E_TICKLER_CPU_USAGE {
    uint32_t TotalCpuUsage;
    uint32_t ProgramCpuUsage;
};

struct S2E_TICKLER_COMMAND {
    S2E_TICKLER_COMMANDS Command;
    union {
        // Command parameters go here
        S2E_TICKLER_CPU_USAGE CpuUsage;
        uint64_t AsciiZ;
    };
};

class Tickler : public Plugin, public IPluginInvoker {

    S2E_PLUGIN
private:
    MemoryMap *m_memory;
    WindowsMonitor *m_monitor;
    CFIChecker *m_cfi_checker;
    ProcessExecutionDetector *m_process;

    uint64_t m_timerCount;
    unsigned m_timerTicks;
    bool m_stopRequested;
    bool m_terminateOnJITIdle;

    uint64_t m_heapSprayingThreshold;
    uint64_t m_cpuUsageThreshold;
    bool m_monitorIdleAfterAutoscroll;
    bool m_generateDumpOnFirstViolation;
    uint64_t m_maxCfiViolations;

public:
    Tickler(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    void onAllProcessesTerminated(S2EExecutionState *state);

    void onCFIViolation(S2EExecutionState *state, bool isReturnViolation);

    void stopIfSegfaultDetected(S2EExecutionState *state);
    void stopIfTooManyCFIViolations(S2EExecutionState *state);
    void stopIfIdle(S2EExecutionState *state);
    void updateAverageCpuUsage(S2EExecutionState *state, const S2E_TICKLER_CPU_USAGE &usage);
    void onWindowInfo(S2EExecutionState *state, const std::string &info);
    void onFYINotification(S2EExecutionState *state, const std::string &info);

    void stopAnalysis(S2EExecutionState *state);
    void stopIfJITCodeNotRunning(S2EExecutionState *state);
    void onTimer(void);

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_TICKLER_H