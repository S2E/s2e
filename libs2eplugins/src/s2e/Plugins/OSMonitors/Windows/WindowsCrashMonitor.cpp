///
/// Copyright (C) 2016, Cyberhaven
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
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include <s2e/Plugins/OSMonitors/Windows/BlueScreenInterceptor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include "WindowsCrashMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(WindowsCrashMonitor, "This plugin aggregates various sources of Windows crashes", "",
                  "WindowsMonitor", "WindowsCrashDumpGenerator", "BlueScreenInterceptor");

void WindowsCrashMonitor::initialize() {
    m_windowsMonitor = s2e()->getPlugin<WindowsMonitor>();
    m_bsodInterceptor = s2e()->getPlugin<BlueScreenInterceptor>();
    m_bsodGenerator = s2e()->getPlugin<WindowsCrashDumpGenerator>();

    auto cfg = s2e()->getConfig();

    // Crash dumps may be heavy, disable them by default
    m_generateDumpOnKernelCrash = cfg->getBool(getConfigKey() + ".generateCrashDumpOnKernelCrash", false);
    m_generateDumpOnUserCrash = cfg->getBool(getConfigKey() + ".generateCrashDumpOnUserCrash", false);

    // Dumps may be vers large, compress them by default
    m_compressDumps = cfg->getBool(getConfigKey() + ".compressDumps", true);

    // Turn this off to let other plugins decide whether to kill the state or not
    // This option only applies to user-space crashes
    m_terminateOnCrash = cfg->getBool(getConfigKey() + ".terminateOnCrash", true);

    // Generate at most this many crash dumps
    m_maxCrashDumpCount = cfg->getInt(getConfigKey() + ".maxCrashDumps", 10);
    *m_crashCount.get() = 0;

    m_bsodInterceptor->onBlueScreen.connect(sigc::mem_fun(*this, &WindowsCrashMonitor::onBlueScreen));
}

void WindowsCrashMonitor::generateCrashDump(S2EExecutionState *state, const vmi::windows::BugCheckDescription *info,
                                            bool isManual) {
    uint64_t *count = m_crashCount.acquire();
    if (*count >= m_maxCrashDumpCount) {
        m_crashCount.release();
        return;
    }
    ++*count;
    m_crashCount.release();

    bool ret;
    std::string path = m_bsodGenerator->getPathForDump(state);

    if (isManual) {
        ret = m_bsodGenerator->generateManualDump(state, path, info);
    } else {
        ret = m_bsodGenerator->generateDump(state, path, info);
    }

    if (!ret) {
        return;
    }

    if (m_compressDumps) {
        compress_file(path);
    }
}

void WindowsCrashMonitor::onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info) {
    if (m_generateDumpOnKernelCrash) {
        generateCrashDump(state, info, false);
    }

    onKernelModeCrash.emit(state, *info);

    // There is no point of letting the state up at this point, the guest is stuck with a BSOD
    s2e()->getExecutor()->terminateState(*state, "BSOD");
}

/*****************************************************************/

void WindowsCrashMonitor::opUserModeCrash(S2EExecutionState *state, uint64_t guestDataPtr,
                                          const S2E_WINDOWS_CRASH_COMMAND &command) {
    WindowsUserModeCrash crash;
    crash.Pid = command.UserModeCrash.Pid;
    crash.ExceptionCode = command.UserModeCrash.ExceptionCode;
    crash.ExceptionAddress = command.UserModeCrash.ExceptionAddress;
    crash.ExceptionFlags = command.UserModeCrash.ExceptionFlags;

    bool ret = true;
    ret &= state->mem()->readString(command.UserModeCrash.ProgramName, crash.ProgramName);
    if (!ret) {
        getWarningsStream(state) << "could not read program name\n";
        return;
    }

    if (m_generateDumpOnUserCrash) {
        crash.CrashDumpHeader.Buffer = command.Dump.Buffer;
        crash.CrashDumpHeader.Size = command.Dump.Size;

        onUserModeCrash.emit(state, crash);

        vmi::windows::BugCheckDescription info;
        info.guestHeader = crash.CrashDumpHeader.Buffer;
        info.headerSize = crash.CrashDumpHeader.Size;
        generateCrashDump(state, &info, true);
    }

    if (m_terminateOnCrash) {
        s2e()->getExecutor()->terminateState(*state, "User mode crash");
    }
}

void WindowsCrashMonitor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                 uint64_t guestDataSize) {
    S2E_WINDOWS_CRASH_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_WINDOWS_CRASH_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case WINDOWS_USERMODE_CRASH: {
            opUserModeCrash(state, guestDataPtr, command);
        } break;

        default: {
            getWarningsStream(state) << "Unknown command\n";
        } break;
    }
}

} // namespace plugins
} // namespace s2e
