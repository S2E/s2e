///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#ifndef S2E_PLUGINS_LINUX_MONITOR_H
#define S2E_PLUGINS_LINUX_MONITOR_H

#include <s2e/monitors/commands/linux.h>

#include "BaseLinuxMonitor.h"

namespace s2e {
namespace plugins {

template <typename T> T &operator<<(T &stream, const S2E_LINUXMON_COMMANDS &c) {
    switch (c) {
        case LINUX_SEGFAULT:
            stream << "SEGFAULT";
            break;
        case LINUX_PROCESS_LOAD:
            stream << "PROCESS_LOAD";
            break;
        case LINUX_TRAP:
            stream << "TRAP";
            break;
        case LINUX_PROCESS_EXIT:
            stream << "PROCESS_EXIT";
            break;
        default:
            stream << "INVALID(" << (int) c << ")";
            break;
    }

    return stream;
}

///
/// \brief Detects the loading/unloading of modules and various errors on the
/// Linux operating system.
///
/// This plugin has been specifically developed for a modified version of the
/// Linux 4.9.3 kernel, which can be accessed at
/// https://github.com/S2E/s2e-linux-kernel.git in the linux-4.9.3 branch.
///
class LinuxMonitor : public BaseLinuxMonitor {
    S2E_PLUGIN
public:
    LinuxMonitor(S2E *s2e) : BaseLinuxMonitor(s2e) {
    }

    void initialize();

private:
    /// Address of the \c current_task object in the Linux kernel (see arch/x86/kernel/cpu/common.c)
    uint64_t m_currentTaskAddr;

    /// Offset of the thread group identifier in the \c task_struct struct (see include/linux/sched.h)
    uint64_t m_taskStructTgidOffset;

    /// Terminate if a trap (e.g. divide by zero) occurs
    bool m_terminateOnTrap;

    //
    // Handle the various commands emitted by the kernel
    //
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *cmd);

    void handleSegfault(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleProcessExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleTrap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleInit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleMemMap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleMemUnmap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleMemProtect(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);

public:
    /// Emitted when a trap occurs in the kernel (e.g. divide by zero, etc.)
    sigc::signal<void, S2EExecutionState *, uint64_t, /* pid */
                 uint64_t,                            /* pc */
                 int /* trapnr */>
        onTrap;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* start */, uint64_t /* size */,
                 uint64_t /* flags */>
        onMemoryMap;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* start */, uint64_t /* size */>
        onMemoryUnmap;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* start */, uint64_t /* size */,
                 uint64_t /* prot */>
        onMemoryProtect;

    // Get the current process identifier
    virtual uint64_t getPid(S2EExecutionState *state);

    /// Get the current thread identifier
    virtual uint64_t getTid(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif
