///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
class LinuxMonitor : public BaseLinuxMonitor<S2E_LINUXMON_COMMAND> {
    S2E_PLUGIN
public:
    // Initialize the plugin
    LinuxMonitor(S2E *s2e);
    virtual void initialize();

private:
    /// Terminate if a trap (e.g. divide by zero) occurs
    bool m_terminateOnTrap;

    //
    // Handle the various commands emitted by the kernel
    //
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                               S2E_LINUXMON_COMMAND &cmd);
    void handleSegfault(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleProcessLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleModuleLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleProcessExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);
    void handleTrap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd);

public:
    /// Emitted when a trap occurs in the kernel (e.g. divide by zero, etc.)
    sigc::signal<void, S2EExecutionState *,
                 uint64_t, // pid
                 uint64_t, // pc
                 int       // trapnr
                 >
        onTrap;

    // Get the current process identifier
    virtual uint64_t getPid(S2EExecutionState *state, uint64_t pc);
    virtual uint64_t getPid(S2EExecutionState *state);

    /// Get the current thread identifier
    virtual uint64_t getTid(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif
