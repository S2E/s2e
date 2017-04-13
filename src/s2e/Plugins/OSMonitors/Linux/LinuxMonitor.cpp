///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include "LinuxMonitor.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxMonitor, "LinuxMonitor S2E plugin", "OSMonitor", "BaseInstructions");

namespace linux {

//
// These are default values specific to version 4.9.3 of the Linux kernel. If
// the user wishes to use different configuration values and/or a different
// version of the kernel, these values should be recalculated as required
//

/// \brief The start address of the kernel
///
/// This is configured in the Linux kernel via the CONFIG_PAGE_OFFSET option.
/// This is the default value for X86
static const uint64_t KERNEL_START_ADDRESS = 0xC0000000;

// TODO Get real stack size from process memory map
static const unsigned STACK_SIZE = 16 * 1024 * 1024;

/// \brief Process identifier offset
///
/// Found with "pahole vmlinux -C task_struct | grep pid". Note that this
/// requires that the kernel be built with debug information.
static const unsigned TASK_STRUCT_PID_OFFSET = 884;

/// \brief Thread group identifier offset
///
/// Found with "pahole vmlinux -C task_struct | grep tgid". Note that this
/// requires that the kernel be built with debug information.
static const unsigned TASK_STRUCT_TGID_OFFSET = 888;

} // namespace linux

///
/// \brief Plugin state for the LinuxMonitor
///
/// It doesn't really do anything more than the \c BaseLinuxMonitorState
///
class LinuxMonitorState : public BaseLinuxMonitorState {
public:
    virtual LinuxMonitorState *clone() const {
        return new LinuxMonitorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LinuxMonitorState();
    }

    virtual ~LinuxMonitorState() {
    }
};

////////////////

LinuxMonitor::LinuxMonitor(S2E *s2e)
    : BaseLinuxMonitor(s2e, linux::KERNEL_START_ADDRESS, linux::STACK_SIZE, S2E_LINUXMON_COMMAND_VERSION) {
}

void LinuxMonitor::initialize() {
    ConfigFile *cfg = s2e()->getConfig();
    m_terminateOnSegfault = cfg->getBool(getConfigKey() + ".terminateOnSegfault", true);
    m_terminateOnTrap = cfg->getBool(getConfigKey() + ".terminateOnTrap", true);
}

uint64_t LinuxMonitor::getPid(S2EExecutionState *state, uint64_t pc) {
    return getPid(state);
}

//
// In the Linux kernel, each thread has its own task_struct that contains:
//  * Its own identifier, the process identifier (PID)
//  * The identifier of the process that started the thread, the thread group
//    (TGID)
//
// Therefore the getPid method returns the TGID and getTid returns the PID.
//

// XXX: this assumes 64-bit kernels!
uint64_t LinuxMonitor::getPid(S2EExecutionState *state) {
    target_ulong tgid;
    target_ulong taskStructPtr = getTaskStructPtr(state);
    target_ulong tgidAddress = taskStructPtr + linux::TASK_STRUCT_TGID_OFFSET;

    if (!state->mem()->readMemoryConcrete(tgidAddress, &tgid, sizeof(tgid))) {
        return -1;
    } else {
        return tgid;
    }
}

uint64_t LinuxMonitor::getTid(S2EExecutionState *state) {
    target_ulong pid;
    target_ulong taskStructPtr = getTaskStructPtr(state);
    target_ulong pidAddress = taskStructPtr + linux::TASK_STRUCT_PID_OFFSET;

    if (!state->mem()->readMemoryConcrete(pidAddress, &pid, sizeof(pid))) {
        return -1;
    } else {
        return pid;
    }
}

void LinuxMonitor::handleSegfault(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    std::string currentName(cmd.currentName, strnlen(cmd.currentName, sizeof(cmd.currentName)));
    getWarningsStream(state) << "Received segfault"
                             << " type=" << cmd.SegFault.fault << " pagedir=" << hexval(state->getPageDir())
                             << " pid=" << hexval(cmd.currentPid) << " name=" << currentName
                             << " pc=" << hexval(cmd.SegFault.pc) << " addr=" << hexval(cmd.SegFault.address) << "\n";

    // Don't switch states until it finishes and gets killed by
    // bootstrap.
    //
    // Need to print a message here to avoid confusion and needless
    // debugging, wondering why the searcher doesn't work anymore.
    getDebugStream(state) << "Blocking searcher until state is terminated\n";
    state->setStateSwitchForbidden(true);

    state->disassemble(getDebugStream(state), cmd.SegFault.pc, 256);

    onSegFault.emit(state, cmd.currentPid, cmd.SegFault.pc);

    if (m_terminateOnSegfault) {
        getDebugStream(state) << "Terminating state: received segfault\n";
        s2e()->getExecutor()->terminateStateEarly(*state, "Segfault");
    }
}

void LinuxMonitor::handleProcessLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    static bool loaded = false;

    if (!loaded) {
        onMonitorLoad.emit(state);
        loaded = true;
    }

    std::string processPath(cmd.ProcessLoad.process_path,
                            strnlen(cmd.ProcessLoad.process_path, sizeof(cmd.ProcessLoad.process_path)));

    getDebugStream(state) << "Process " << processPath << " loaded"
                          << " entry_point=" << hexval(cmd.ProcessLoad.entry_point)
                          << " pid=" << hexval(cmd.ProcessLoad.process_id)
                          << " start_code=" << hexval(cmd.ProcessLoad.start_code)
                          << " end_code=" << hexval(cmd.ProcessLoad.end_code)
                          << " start_data=" << hexval(cmd.ProcessLoad.start_data)
                          << " end_data=" << hexval(cmd.ProcessLoad.end_data)
                          << " start_stack=" << hexval(cmd.ProcessLoad.start_stack) << "\n";

    llvm::StringRef file(processPath);

    onProcessLoad.emit(state, state->getPageDir(), cmd.ProcessLoad.process_id, llvm::sys::path::stem(file));

    ModuleDescriptor mod;
    mod.Name = llvm::sys::path::stem(file);
    mod.Path = file.str();
    mod.AddressSpace = state->getPageDir();
    mod.Pid = cmd.ProcessLoad.process_id;
    mod.LoadBase = cmd.ProcessLoad.start_code;
    mod.NativeBase = cmd.ProcessLoad.start_code;
    mod.Size = cmd.ProcessLoad.end_data - cmd.ProcessLoad.start_code;
    mod.EntryPoint = cmd.ProcessLoad.entry_point;
    mod.DataBase = cmd.ProcessLoad.start_data;
    mod.DataSize = cmd.ProcessLoad.end_data - cmd.ProcessLoad.start_data;
    mod.StackTop = cmd.ProcessLoad.start_stack;

    getDebugStream(state) << mod << "\n";

    onModuleLoad.emit(state, mod);

    DECLARE_PLUGINSTATE(LinuxMonitorState, state);
    plgState->saveModule(mod);
}

void LinuxMonitor::handleModuleLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getWarningsStream(state) << "Module load not yet implemented\n";
}

void LinuxMonitor::handleProcessExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    onProcessUnload.emit(state, state->getPageDir(), cmd.currentPid);

    DECLARE_PLUGINSTATE(LinuxMonitorState, state);
    const ModuleDescriptor *mod = plgState->getModule(cmd.currentPid);
    if (!mod) {
        return;
    }

    getDebugStream(state) << "Removing task (pid=" << cmd.currentPid << ", cr3=" << mod->AddressSpace
                          << ", exitCode=" << cmd.ProcessExit.code << ") record from collector.\n";
    plgState->removeModule(*mod);

    return;
}

void LinuxMonitor::handleTrap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getWarningsStream(state) << "Received trap"
                             << " pid=" << hexval(cmd.currentPid) << " pc=" << hexval(cmd.Trap.pc)
                             << " trapnr=" << hexval(cmd.Trap.trapnr) << " signr=" << hexval(cmd.Trap.signr)
                             << " err_code=" << cmd.Trap.error_code << "\n";

    getDebugStream(state) << "Blocking searcher until state is terminated\n";
    state->setStateSwitchForbidden(true);

    onTrap.emit(state, cmd.currentPid, cmd.Trap.pc, cmd.Trap.trapnr);

    if (m_terminateOnTrap) {
        getDebugStream(state) << "Terminating state: received trap\n";
        s2e()->getExecutor()->terminateStateEarly(*state, "Trap");
    }
}

void LinuxMonitor::handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                                 S2E_LINUXMON_COMMAND &cmd) {
    switch (cmd.Command) {
        case LINUX_SEGFAULT:
            handleSegfault(state, cmd);
            break;

        case LINUX_PROCESS_LOAD:
            handleProcessLoad(state, cmd);
            break;

        case LINUX_MODULE_LOAD:
            handleModuleLoad(state, cmd);
            break;

        case LINUX_TRAP:
            handleTrap(state, cmd);
            break;

        case LINUX_PROCESS_EXIT:
            handleProcessExit(state, cmd);
            break;
    }
}

} // namespace plugins
} // namespace s2e
