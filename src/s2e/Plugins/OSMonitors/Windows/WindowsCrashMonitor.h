///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_WindowsCrashMonitor_H
#define S2E_PLUGINS_WindowsCrashMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>

#include <s2e/Plugins/OSMonitors/Windows/BlueScreenInterceptor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.h>

namespace s2e {
namespace plugins {

struct WindowsUserModeCrash {
    std::string ProgramName;
    uint64_t Pid;
    uint64_t ExceptionCode;
    uint64_t ExceptionAddress;
    uint64_t ExceptionFlags;

    struct {
        uint64_t Buffer;
        uint64_t Size;
    } CrashDumpHeader;
};

struct S2E_WINDOWS_USERMODE_CRASH {
    uint64_t ProgramName;
    uint64_t Pid;
    uint64_t ExceptionCode;
    uint64_t ExceptionAddress;
    uint64_t ExceptionFlags;
};

enum S2E_WINDOWS_CRASH_COMMANDS { WINDOWS_USERMODE_CRASH };

struct S2E_CRASHDUMP_OPAQUE {
    uint64_t Buffer;
    uint64_t Size;
};

struct S2E_WINDOWS_CRASH_COMMAND {
    S2E_WINDOWS_CRASH_COMMANDS Command;
    union {
        S2E_WINDOWS_USERMODE_CRASH UserModeCrash;
    };
    /* Optional, used by the crash dump plugin. */
    S2E_CRASHDUMP_OPAQUE Dump;
};

class WindowsCrashMonitor : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    WindowsCrashMonitor(S2E *s2e) : Plugin(s2e) {
    }

    sigc::signal<void, S2EExecutionState *, const WindowsUserModeCrash &> onUserModeCrash;

    sigc::signal<void, S2EExecutionState *, const vmi::windows::BugCheckDescription &> onKernelModeCrash;

    void initialize();
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    WindowsMonitor *m_windowsMonitor;
    BlueScreenInterceptor *m_bsodInterceptor;
    WindowsCrashDumpGenerator *m_bsodGenerator;

    bool m_generateCrashDump;
    bool m_compressDumps;
    bool m_terminateOnCrash;
    int m_maxCrashDumpCount;

    S2ESynchronizedObject<uint64_t> m_crashCount;

    void generateCrashDump(S2EExecutionState *state, const vmi::windows::BugCheckDescription *info, bool isManual);
    void onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info);
    void opUserModeCrash(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_WINDOWS_CRASH_COMMAND &command);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_WindowsCrashMonitor_H
