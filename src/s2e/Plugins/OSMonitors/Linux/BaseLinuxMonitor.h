///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BASE_LINUX_MONITOR_H
#define S2E_PLUGINS_BASE_LINUX_MONITOR_H

#include <s2e/Plugin.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>

#include <map>
#include <sstream>

extern "C" {
extern CPUX86State *env;
}

using namespace klee;

namespace s2e {
namespace plugins {

class MemoryMap;

namespace linux_common {

// TODO Get the real stack size from the process memory map
static const uint64_t STACK_SIZE = 16 * 1024 * 1024;

} // namespace linux_common

///
/// \brief Abstract base plugin for X86 Linux monitors, including the Linux and
/// CGC monitors
///
/// This class contains a number of virtual getter methods that return values specific to the kernel in use.
///
class BaseLinuxMonitor : public OSMonitor, public IPluginInvoker {
protected:
    Vmi *m_vmi;

    MemoryMap *m_map;

    /// Start address of the Linux kernel
    uint64_t m_kernelStartAddress;

    /// Offset of the process identifier in the \c task_struct struct (see include/linux/sched.h)
    uint64_t m_taskStructPidOffset;

    /// Terminate if a segment fault occurs
    bool m_terminateOnSegfault;

    uint64_t m_commandVersion;
    uint64_t m_commandSize;

    void loadKernelImage(S2EExecutionState *state, uint64_t start_kernel) {
        ModuleDescriptor mod, vmlinux;
        mod.Name = "vmlinux";

        auto exe = m_vmi->getFromDisk(mod, false);
        if (!exe) {
            getWarningsStream(state) << "Could not load vmlinux from disk\n";
            return;
        }

        Vmi::toModuleDescriptor(vmlinux, exe);

        vmlinux.Name = vmlinux.Path = "vmlinux";
        vmlinux.LoadBase = start_kernel;
        vmlinux.AddressSpace = 0;
        vmlinux.Pid = 0;
        onModuleLoad.emit(state, vmlinux);
    }

    bool verifyLinuxCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, uint8_t *cmd);

public:
    /// Emitted when a segment fault occurs in the kernel
    sigc::signal<void, S2EExecutionState *, uint64_t, /* pid */ uint64_t /* pc */> onSegFault;

    ///
    /// Create a new monitor for the Linux kernel
    ///
    /// \param s2e The global S2E object
    ///
    BaseLinuxMonitor(S2E *s2e) : OSMonitor(s2e) {
    }

    virtual uint64_t getKernelStart() const {
        return m_kernelStartAddress;
    }

    /// Get the base address and size of the stack
    virtual bool getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size);

    ///
    /// \brief Handle a custom command emitted by the kernel
    ///
    /// This occurs in the following steps:
    ///  - Command is verified
    ///  - The \c onCustomInstruction signal is emitted with \c done set to \c false
    ///  - The command is handled by the specific implementation. Note that the data contained within the command can
    ///    be modified at this point
    ///  - The \c onCustomInstruction signal is emitted with \c done set to \c true
    ///
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
        uint8_t cmd[guestDataSize];
        memset(cmd, 0, guestDataSize);

        if (!verifyLinuxCommand(state, guestDataPtr, guestDataSize, cmd)) {
            return;
        }

        handleCommand(state, guestDataPtr, guestDataSize, cmd);
    }

    ///
    /// Handle the given command with the data provided
    ///
    /// \param state The S2E state
    /// \param guestDataPtr Pointer to the raw data emitted by the kernel
    /// \param guestDataSize Size of the raw data emitted by the kernel
    /// \param cmd The custom instruction emitted by the kernel
    ///
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *cmd) = 0;

    /// Get the name of the process with the given PID
    virtual bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) {
        return false;
    }

    virtual void handleKernelPanic(S2EExecutionState *state, uint64_t message, uint64_t messageSize) {
        std::string str = "kernel panic";
        state->mem()->readString(message, str, messageSize);
        g_s2e->getExecutor()->terminateStateEarly(*state, str);
    }
};

} // namespace plugins
} // namespace s2e

#endif
