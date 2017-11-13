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
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <map>
#include <sstream>

extern "C" {
extern CPUX86State *env;
}

using namespace klee;

namespace s2e {
namespace plugins {

namespace linux_common {

// TODO Get the real stack size from the process memory map
static const uint64_t STACK_SIZE = 16 * 1024 * 1024;

} // namespace linux_common

///
/// \brief Base state for X86 Linux monitors, including the Linux and CGC monitors
///
class BaseLinuxMonitorState : public PluginState {
protected:
    /// Map of PIDs to modules
    std::map<uint64_t, ModuleDescriptor> m_modulesByPid;

public:
    virtual ~BaseLinuxMonitorState() {
    }

    virtual BaseLinuxMonitorState *clone() const {
        return new BaseLinuxMonitorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *state) {
        return new BaseLinuxMonitorState();
    }

    const ModuleDescriptor *getModule(uint64_t pid) const {
        auto it = m_modulesByPid.find(pid);
        if (it == m_modulesByPid.end()) {
            return nullptr;
        } else {
            return &(it->second);
        }
    }

    void saveModule(const ModuleDescriptor &mod) {
        m_modulesByPid[mod.Pid] = mod;
    }

    void removeModule(const ModuleDescriptor &mod) {
        m_modulesByPid.erase(mod.Pid);
    }
};

///
/// \brief Abstract base plugin for X86 Linux monitors, including the Linux and
/// CGC monitors
///
/// This class contains a number of virtual getter methods that return values specific to the kernel in use.
///
/// \tparam CmdT The type of command that will be emitted by the kernel and captured by a Linux monitor plugin
/// \tparam CmdVersion The command version that is expected to be emitted from the kernel when an event occurs
///
template <typename CmdT, uint64_t CmdVersion>
class BaseLinuxMonitor : public OSMonitor, public BaseInstructionsPluginInvokerInterface {
protected:
    /// Start address of the Linux kernel
    uint64_t m_kernelStartAddress;

    /// Offset of the process identifier in the \c task_struct struct (see include/linux/sched.h)
    uint64_t m_taskStructPidOffset;

    /// Terminate if a segment fault occurs
    bool m_terminateOnSegfault;

    /// Verify that the custom  at the given ptr address is valid
    bool verifyCustomInstruction(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, CmdT &cmd) {
        // Validate the size of the instruction
        s2e_assert(state, guestDataSize == sizeof(cmd),
                   "Invalid command size " << guestDataSize << " != " << sizeof(cmd) << " from pagedir="
                                           << hexval(state->getPageDir()) << " pc=" << hexval(state->getPc()));

        // Read any symbolic bytes
        std::ostringstream symbolicBytes;
        for (unsigned i = 0; i < sizeof(cmd); ++i) {
            ref<Expr> t = state->readMemory8(guestDataPtr + i);
            if (!t.isNull() && !isa<ConstantExpr>(t)) {
                symbolicBytes << "  " << hexval(i, 2) << "\n";
            }
        }

        if (symbolicBytes.str().length()) {
            getWarningsStream(state) << "Command has symbolic bytes at " << symbolicBytes.str() << "\n";
        }

        // Read the instruction
        bool ok = state->mem()->readMemoryConcrete(guestDataPtr, &cmd, sizeof(cmd));
        s2e_assert(state, ok, "Failed to read instruction memory");

        // Validate the instruction's version
        if (cmd.version != CmdVersion) {
            std::ostringstream os;

            for (unsigned i = 0; i < sizeof(cmd); ++i) {
                os << hexval(((uint8_t *) &cmd)[i]) << " ";
            }

            getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

            s2e_assert(state, false, "Invalid command version " << hexval(cmd.version) << " != " << hexval(CmdVersion)
                                                                << " from pagedir=" << hexval(state->getPageDir())
                                                                << " pc=" << hexval(state->getPc()));
        }

        return true;
    }

public:
    /// Emitted when one of the custom instructions is executed in the kernel
    sigc::signal<void, S2EExecutionState *, const CmdT &, bool /* done */> onCustomInstruction;

    /// Emitted when a segment fault occurs in the kernel
    sigc::signal<void, S2EExecutionState *, uint64_t, /* pid */ uint64_t /* pc */> onSegFault;

    ///
    /// Create a new monitor for the Linux kernel
    ///
    /// \param s2e The global S2E object
    ///
    BaseLinuxMonitor(S2E *s2e) : OSMonitor(s2e) {
    }

    /// Returns \c true if the given program counter is located within the kernel
    virtual bool isKernelAddress(uint64_t pc) const {
        return pc >= m_kernelStartAddress;
    }

    /// Get the page directory
    virtual uint64_t getAddressSpace(S2EExecutionState *state, uint64_t pc) {
        if (pc >= m_kernelStartAddress) {
            return 0;
        } else {
            return state->getPageDir();
        }
    }

    /// Get the base address and size of the stack
    virtual bool getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size) {
        ModuleExecutionDetector *detector = s2e()->template getPlugin<ModuleExecutionDetector>();
        assert(detector);

        const ModuleDescriptor *module = detector->getCurrentDescriptor(state);
        if (!module) {
            return false;
        }

        *base = module->StackTop - linux_common::STACK_SIZE;
        *size = linux_common::STACK_SIZE;

        // 'pop' instruction can be executed when ESP is set to STACK_TOP
        *size += state->getPointerSize() + 1;

        return true;
    }

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
        CmdT cmd;

        if (!verifyCustomInstruction(state, guestDataPtr, guestDataSize, cmd)) {
            return;
        }

        onCustomInstruction.emit(state, cmd, false);
        handleCommand(state, guestDataPtr, guestDataSize, cmd);
        onCustomInstruction.emit(state, cmd, true);
    }

    ///
    /// Handle the given command with the data provided
    ///
    /// \param state The S2E state
    /// \param guestDataPtr Pointer to the raw data emitted by the kernel
    /// \param guestDataSize Size of the raw data emitted by the kernel
    /// \param cmd The custom instruction emitted by the kernel
    ///
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, CmdT &cmd) = 0;

    /// Get the name of the process with the given PID
    virtual bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) {
        DECLARE_PLUGINSTATE_CONST(BaseLinuxMonitorState, state);
        const ModuleDescriptor *mod = plgState->getModule(pid);

        if (mod) {
            name = mod->Name;

            return true;
        } else {
            return false;
        }
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
