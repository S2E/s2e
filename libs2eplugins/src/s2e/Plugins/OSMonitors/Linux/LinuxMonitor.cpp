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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include "LinuxMonitor.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxMonitor, "LinuxMonitor S2E plugin", "OSMonitor", "BaseInstructions", "Vmi");

namespace {
class LinuxMonitorState : public BaseLinuxMonitorState {
public:
    virtual LinuxMonitorState *clone() const {
        return new LinuxMonitorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LinuxMonitorState();
    }
};

} // namespace

void LinuxMonitor::initialize() {
    ConfigFile *cfg = s2e()->getConfig();

    m_vmi = s2e()->getPlugin<Vmi>();

    // XXX: this is a circular dependency, will require further refactoring
    m_map = s2e()->getPlugin<MemoryMap>();
    if (!m_map) {
        getWarningsStream() << "Requires MemoryMap\n";
        exit(-1);
    }

    m_terminateOnSegfault = cfg->getBool(getConfigKey() + ".terminateOnSegfault", true);
    m_terminateOnTrap = cfg->getBool(getConfigKey() + ".terminateOnTrap", true);

    m_commandSize = sizeof(S2E_LINUXMON_COMMAND);
    m_commandVersion = S2E_LINUXMON_COMMAND_VERSION;

    s2e()->getCorePlugin()->onInitializationComplete.connect(
        sigc::mem_fun(*this, &LinuxMonitor::onInitializationComplete));
}

void LinuxMonitor::onInitializationComplete(S2EExecutionState *state) {
    // Initialize the plugin state before BaseLinuxMonitor tries to access it.
    getPluginState(state, &LinuxMonitorState::factory);
}

void LinuxMonitor::handleSegfault(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getWarningsStream(state) << "Received segfault"
                             << " type=" << cmd.SegFault.fault << " pagedir=" << hexval(state->regs()->getPageDir())
                             << " pid=" << hexval(cmd.CurrentTask.tgid) << " pc=" << hexval(cmd.SegFault.pc)
                             << " addr=" << hexval(cmd.SegFault.address) << "\n";

    // Don't switch states until it finishes and gets killed by
    // bootstrap.
    //
    // Need to print a message here to avoid confusion and needless
    // debugging, wondering why the searcher doesn't work anymore.
    getDebugStream(state) << "Blocking searcher until state is terminated\n";
    state->setStateSwitchForbidden(true);

    state->disassemble(getDebugStream(state), cmd.SegFault.pc, 256);

    onSegFault.emit(state, cmd.CurrentTask.tgid, cmd.SegFault.pc);

    if (m_terminateOnSegfault) {
        getDebugStream(state) << "Terminating state: received segfault\n";
        s2e()->getExecutor()->terminateState(*state, "Segfault");
    }
}

void LinuxMonitor::handleProcessExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    auto pd = state->regs()->getPageDir();
    getDebugStream(state) << "Process exit pid=" << hexval(cmd.CurrentTask.tgid)
                          << " tid=" << hexval(cmd.CurrentTask.pid) << " cr3=" << hexval(pd)
                          << " exitCode=" << cmd.ProcessExit.code << "\n";

    onProcessUnload.emit(state, pd, cmd.CurrentTask.tgid, cmd.ProcessExit.code);
}

void LinuxMonitor::handleThreadExit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    auto pd = state->regs()->getPageDir();
    getDebugStream(state) << "Thread exit pid=" << hexval(cmd.CurrentTask.tgid)
                          << " tid=" << hexval(cmd.CurrentTask.pid) << " cr3=" << hexval(pd)
                          << " exitCode=" << cmd.ProcessExit.code << "\n";

    ThreadDescriptor desc;
    desc.Pid = cmd.CurrentTask.tgid;
    desc.Tid = cmd.CurrentTask.pid;
    onThreadExit.emit(state, desc);
}

void LinuxMonitor::handleTrap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getWarningsStream(state) << "Received trap"
                             << " pid=" << hexval(cmd.CurrentTask.tgid) << " pc=" << hexval(cmd.Trap.pc)
                             << " trapnr=" << hexval(cmd.Trap.trapnr) << " signr=" << hexval(cmd.Trap.signr)
                             << " err_code=" << cmd.Trap.error_code << "\n";

    getDebugStream(state) << "Blocking searcher until state is terminated\n";
    state->setStateSwitchForbidden(true);

    onTrap.emit(state, cmd.CurrentTask.tgid, cmd.Trap.pc, cmd.Trap.trapnr);

    if (m_terminateOnTrap) {
        getDebugStream(state) << "Terminating state: received trap\n";
        s2e()->getExecutor()->terminateState(*state, "Trap");
    }
}

void LinuxMonitor::handleInit(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getDebugStream(state) << "Received kernel init"
                          << " page_offset=" << hexval(cmd.Init.page_offset) << "\n";

    m_kernelStartAddress = cmd.Init.page_offset;

    completeInitialization(state);

    loadKernelImage(state, cmd.Init.start_kernel);
}

void LinuxMonitor::handleMemMap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getDebugStream(state) << "mmap pid=" << hexval(cmd.CurrentTask.tgid) << " addr=" << hexval(cmd.MemMap.address)
                          << " size=" << hexval(cmd.MemMap.size) << " prot=" << hexval(cmd.MemMap.prot)
                          << " flag=" << hexval(cmd.MemMap.flag) << " pgoff=" << hexval(cmd.MemMap.pgoff) << "\n";

    // A negative address for mmap indicates failure
    if (int64_t(cmd.MemMap.address) < 0) {
        getWarningsStream(state) << "mmap failed: " << hexval(cmd.MemMap.address) << "\n";
        return;
    }

    onMemoryMap.emit(state, cmd.CurrentTask.tgid, cmd.MemMap.address, cmd.MemMap.size, cmd.MemMap.prot);
}

void LinuxMonitor::handleMemUnmap(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getDebugStream(state) << "munmap pid=" << hexval(cmd.CurrentTask.tgid) << " start=" << hexval(cmd.MemUnmap.start)
                          << " end=" << hexval(cmd.MemUnmap.end) << "\n";

    uint64_t size = cmd.MemUnmap.end - cmd.MemUnmap.start;
    onMemoryUnmap.emit(state, cmd.CurrentTask.tgid, cmd.MemUnmap.start, size);
}

void LinuxMonitor::handleMemProtect(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    getDebugStream(state) << "mprotect pid=" << hexval(cmd.CurrentTask.tgid)
                          << " start=" << hexval(cmd.MemProtect.start) << " size=" << hexval(cmd.MemProtect.size)
                          << " prot=" << hexval(cmd.MemProtect.prot) << "\n";

    onMemoryProtect.emit(state, cmd.CurrentTask.tgid, cmd.MemProtect.start, cmd.MemProtect.size, cmd.MemProtect.prot);
}

void LinuxMonitor::handleTaskSwitch(S2EExecutionState *state, const S2E_LINUXMON_COMMAND &cmd) {
    BaseLinuxMonitor::handleTaskSwitch(state, cmd.CurrentTask, cmd.TaskSwitch);
}

void LinuxMonitor::handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *_cmd) {
    S2E_LINUXMON_COMMAND &cmd = *(S2E_LINUXMON_COMMAND *) _cmd;
    switch (cmd.Command) {
        case LINUX_SEGFAULT:
            handleSegfault(state, cmd);
            break;

        case LINUX_PROCESS_LOAD:
            handleProcessLoad(state, cmd.CurrentTask.tgid, cmd.ProcessLoad);
            break;

        case LINUX_MODULE_LOAD:
            handleModuleLoad(state, cmd.CurrentTask.tgid, cmd.ModuleLoad);
            break;

        case LINUX_TRAP:
            handleTrap(state, cmd);
            break;

        case LINUX_PROCESS_EXIT:
            handleProcessExit(state, cmd);
            break;

        case LINUX_THREAD_EXIT:
            handleThreadExit(state, cmd);
            break;

        case LINUX_INIT:
            handleInit(state, cmd);
            break;

        case LINUX_KERNEL_PANIC:
            handleKernelPanic(state, cmd.Panic.message, cmd.Panic.message_size);
            break;

        case LINUX_MEMORY_MAP:
            handleMemMap(state, cmd);
            break;

        case LINUX_MEMORY_UNMAP:
            handleMemUnmap(state, cmd);
            break;

        case LINUX_MEMORY_PROTECT:
            handleMemProtect(state, cmd);
            break;

        case LINUX_TASK_SWITCH:
            handleTaskSwitch(state, cmd);
            break;
    }
}

} // namespace plugins
} // namespace s2e
