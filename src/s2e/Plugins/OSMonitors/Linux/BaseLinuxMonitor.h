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

// from arch/x86/include/asm/page_types.h
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

// from arch/x86/include/asm/page_32_types.h
#define THREAD_SIZE_ORDER 1
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

/// Pointer to the address of ESP0 in the Task State Segment (TSS).
/// ESP0 is the stack pointer to load when in kernel mode
#define TSS_ESP0_OFFSET 4

namespace s2e {
namespace plugins {

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
/// This class contains a number of virtual getter methods that return values
/// specific to the kernel in use.
///
/// \tparam CmdT The type of command that will be emitted by the kernel and
/// captured by a Linux monitor plugin
///
template <typename CmdT> class BaseLinuxMonitor : public OSMonitor, public BaseInstructionsPluginInvokerInterface {
protected:
    /// Start address of the kernel
    const uint64_t m_kernelStartAddress;

    /// Size of the stack
    const unsigned m_stackSize;

    /// The version of the monitor command to validate against
    const uint64_t m_commandVersion;

    /// Terminate if a segment fault occurs
    bool m_terminateOnSegfault;

    /// Get the base address to the \c task_struct in the kernel
    target_ulong getTaskStructPtr(S2EExecutionState *state) {
        target_ulong esp0;
        target_ulong esp0Addr = env->tr.base + TSS_ESP0_OFFSET;

        if (!state->mem()->readMemoryConcrete(esp0Addr, &esp0, sizeof(esp0))) {
            return -1;
        }

        // Based on the "current_stack" function in arch/x86/kernel/irq_32.c
        target_ulong currentThreadInfo = esp0 & ~(THREAD_SIZE - 1);
        target_ulong taskStructPtr;

        if (!state->mem()->readMemoryConcrete(currentThreadInfo, &taskStructPtr, sizeof(taskStructPtr))) {
            return -1;
        }

        return taskStructPtr;
    }

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
        if (cmd.version != m_commandVersion) {
            std::ostringstream os;

            for (unsigned i = 0; i < sizeof(cmd); ++i) {
                os << hexval(((uint8_t *) &cmd)[i]) << " ";
            }

            getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

            s2e_assert(state, false, "Invalid command version " << hexval(cmd.version)
                                                                << " != " << hexval(m_commandVersion)
                                                                << " from pagedir=" << hexval(state->getPageDir())
                                                                << " pc=" << hexval(state->getPc()));
        }

        return true;
    }

public:
    /// Emitted when one of the custom instructions is executed in the kernel
    sigc::signal<void, S2EExecutionState *, const CmdT &,
                 bool // done
                 >
        onCustomInstruction;

    /// Emitted when a segment fault occurs in the kernel
    sigc::signal<void, S2EExecutionState *,
                 uint64_t, // pid
                 uint64_t  // pc
                 >
        onSegFault;

    ///
    /// Create a new monitor for the Linux kernel
    ///
    /// \param s2e The global S2E object
    /// \param startAddr The kernel's start address
    /// \param stackSize Size of the stack
    /// \param cmdVer The command identifier emitted from the kernel when an event occurs
    ///
    BaseLinuxMonitor(S2E *s2e, uint64_t startAddr, unsigned stackSize, uint64_t cmdVer)
        : OSMonitor(s2e), m_kernelStartAddress(startAddr), m_stackSize(stackSize), m_commandVersion(cmdVer) {
    }

    //
    // None of these methods are implemented by the Linux monitor
    //

    virtual bool getImports(S2EExecutionState *state, const ModuleDescriptor &desc, vmi::Imports &I) {
        return false;
    }

    virtual bool getExports(S2EExecutionState *state, const ModuleDescriptor &desc, vmi::Exports &E) {
        return false;
    }

    virtual bool getRelocations(S2EExecutionState *state, const ModuleDescriptor &desc, vmi::Relocations &R) {
        return false;
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
        ModuleExecutionDetector *detector = (ModuleExecutionDetector *) s2e()->getPlugin("ModuleExecutionDetector");
        assert(detector);

        const ModuleDescriptor *module = detector->getCurrentDescriptor(state);
        if (!module) {
            return false;
        }

        *base = module->StackTop - m_stackSize;
        *size = m_stackSize;

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
};

} // namespace plugins
} // namespace s2e

#endif
