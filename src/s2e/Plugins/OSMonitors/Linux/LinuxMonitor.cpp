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

uint64_t LinuxMonitor::getPid(S2EExecutionState *state) {
    target_ulong currentTask;

    if (!state->mem()->readMemoryConcrete(m_currentTaskAddr, &currentTask, sizeof(currentTask))) {
        return -1;
    }

    // In the kernel the `pid_t` type is just a typedef for `int` (see include/uapi/asm-generic/posix_types.h)
    int pid;
    target_ulong pidAddress = currentTask + m_taskStructTgidOffset;

    if (!state->mem()->readMemoryConcrete(pidAddress, &pid, sizeof(pid))) {
        return -1;
    } else {
        return pid;
    }
}

uint64_t LinuxMonitor::getTid(S2EExecutionState *state) {
    target_ulong currentTask;

    if (!state->mem()->readMemoryConcrete(m_currentTaskAddr, &currentTask, sizeof(currentTask))) {
        return -1;
    }

    target_ulong tid;
    target_ulong tidAddress = m_currentTaskAddr + m_taskStructPidOffset;

    if (!state->mem()->readMemoryConcrete(tidAddress, &tid, sizeof(tid))) {
        return -1;
    } else {
        return tid;
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
    if (!m_initialized) {
        m_initialized = true;
        onMonitorLoad.emit(state);
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
    onProcessUnload.emit(state, state->getPageDir(), cmd.currentPid, cmd.ProcessExit.code);

    DECLARE_PLUGINSTATE(LinuxMonitorState, state);
    const ModuleDescriptor *mod = plgState->getModule(cmd.currentPid);
    if (!mod) {
        return;
    }

    getDebugStream(state) << "Removing task (pid=" << hexval(cmd.currentPid) << ", cr3=" << hexval(mod->AddressSpace)
                          << ", exitCode=" << cmd.ProcessExit.code << ") record from collector.\n";
    plgState->removeModule(*mod);
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

void LinuxMonitor::handleInit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getDebugStream(state) << "Received kernel init"
                          << " page_offset=" << hexval(cmd.Init.page_offset)
                          << " &current_task=" << hexval(cmd.Init.current_task_address)
                          << " task_struct.pid offset=" << cmd.Init.task_struct_pid_offset
                          << " task_struct.tgid offset=" << cmd.Init.task_struct_tgid_offset << "\n";

    m_kernelStartAddress = cmd.Init.page_offset;
    m_currentTaskAddr = cmd.Init.current_task_address;
    m_taskStructPidOffset = cmd.Init.task_struct_pid_offset;
    m_taskStructTgidOffset = cmd.Init.task_struct_tgid_offset;
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

        case LINUX_INIT:
            handleInit(state, cmd);
            break;

        case LINUX_KERNEL_PANIC:
            handleKernelPanic(state, cmd.Panic.message, cmd.Panic.message_size);
            break;
    }
}

} // namespace plugins
} // namespace s2e
