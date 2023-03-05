///
/// Copyright (C) 2014-2018, Cyberhaven
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

#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include "BaseLinuxMonitor.h"

namespace s2e {
namespace plugins {

/// Verify that the custom  at the given ptr address is valid
bool BaseLinuxMonitor::verifyLinuxCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                                          uint8_t *cmd) {
    // Validate the size of the instruction
    s2e_assert(state, guestDataSize == m_commandSize,
               "Invalid command size " << guestDataSize << " != " << m_commandSize
                                       << " from pagedir=" << hexval(state->regs()->getPageDir())
                                       << " pc=" << hexval(state->regs()->getPc()));

    // Read any symbolic bytes
    std::ostringstream symbolicBytes;
    for (unsigned i = 0; i < guestDataSize; ++i) {
        ref<Expr> t = state->mem()->read(guestDataPtr + i);
        if (t && !isa<ConstantExpr>(t)) {
            symbolicBytes << "  " << hexval(i, 2) << "\n";
        }
    }

    if (symbolicBytes.str().length()) {
        getWarningsStream(state) << "Command has symbolic bytes at " << symbolicBytes.str() << "\n";
    }

    // Read the instruction
    bool ok = state->mem()->read(guestDataPtr, cmd, guestDataSize);
    s2e_assert(state, ok, "Failed to read instruction memory");

    // Validate the instruction's version

    // The version field comes always first in all commands
    uint64_t version = *(uint64_t *) cmd;

    if (version != m_commandVersion) {
        std::ostringstream os;

        for (unsigned i = 0; i < guestDataSize; ++i) {
            os << hexval(cmd[i]) << " ";
        }

        getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

        s2e_assert(state, false,
                   "Invalid command version " << hexval(version) << " != " << hexval(m_commandVersion)
                                              << " from pagedir=" << hexval(state->regs()->getPageDir())
                                              << " pc=" << hexval(state->regs()->getPc()));
    }

    return true;
}

///
/// \brief Get the process id for the current state
///
/// In the Linux kernel, each thread has its own task_struct that contains:
///  * Its own identifier, the process identifier (PID)
///  * The identifier of the process that started the thread, the thread group
///    (TGID)
///
/// Therefore the getPid method returns the TGID and getTid returns the PID.
///
/// \return The process id
///
uint64_t BaseLinuxMonitor::getPid(S2EExecutionState *state) {
    auto plgState = state->getPluginState<BaseLinuxMonitorState>(this);
    if (plgState) {
        return plgState->getTgid();
    } else {
        return -1;
    }
}

uint64_t BaseLinuxMonitor::getTid(S2EExecutionState *state) {
    auto plgState = state->getPluginState<BaseLinuxMonitorState>(this);
    if (plgState) {
        return plgState->getPid();
    } else {
        return -1;
    }
}

void BaseLinuxMonitor::handleTaskSwitch(S2EExecutionState *state, const S2E_LINUXMON_TASK &CurrentTask,
                                        const S2E_LINUXMON_COMMAND_TASK_SWITCH &TaskSwitch) {
    auto plgState = state->getPluginState<BaseLinuxMonitorState>(this);

    if (!plgState) {
        getWarningsStream(state) << "BaseLinuxMonitorState is not initialized\n";
        return;
    }

    auto curPid = plgState->getPid();
    auto curTgid = plgState->getTgid();

    if (curPid != -1 && curTgid != -1) {
        bool mismatch = false;
        if (TaskSwitch.prev.pid != curPid) {
            getWarningsStream(state) << "task pid mismatch\n";
            mismatch = true;
        }

        if (TaskSwitch.prev.tgid != curTgid) {
            getWarningsStream(state) << "task tgid mismatch\n";
            mismatch = true;
        }

        if (mismatch) {
            getWarningsStream(state) << "cur.tgid=" << hexval(CurrentTask.tgid)
                                     << " cur.pid=" << hexval(CurrentTask.pid) << " cache.tgid=" << hexval(curTgid)
                                     << " cache.pid=" << hexval(curPid) << " prev.tgid=" << hexval(TaskSwitch.prev.tgid)
                                     << " prev.pid=" << hexval(TaskSwitch.prev.pid)
                                     << " next.tgid=" << hexval(TaskSwitch.next.tgid)
                                     << " next.pid=" << hexval(TaskSwitch.next.pid) << "\n";
        }
    }

    plgState->setPidTgid(TaskSwitch.next.pid, TaskSwitch.next.tgid);

    onProcessOrThreadSwitch.emit(state);
}

bool BaseLinuxMonitor::getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size) {
    auto pid = getPid(state);

    uint64_t start, end;
    MemoryMapRegionType type;

    if (!m_map->lookupRegion(state, pid, state->regs()->getSp(), start, end, type)) {
        return false;
    }

    *base = start;
    *size = end - start;

    return true;
}

void BaseLinuxMonitor::handleProcessLoad(S2EExecutionState *state, uint64_t pid,
                                         const S2E_LINUXMON_COMMAND_PROCESS_LOAD &procLoad) {
    completeInitialization(state);

    std::string processPath;
    if (!state->mem()->readString(procLoad.process_path, processPath)) {
        getWarningsStream(state) << "could not read process path of pid " << hexval(pid) << "\n";
    }

    getDebugStream(state) << "Process " << processPath << " loaded"
                          << " pid=" << hexval(pid) << "\n";

    llvm::StringRef file(processPath);

    onProcessLoad.emit(state, state->regs()->getPageDir(), pid, std::string(llvm::sys::path::filename(file)));
}

void BaseLinuxMonitor::handleModuleLoad(S2EExecutionState *state, uint64_t pid,
                                        const S2E_LINUXMON_COMMAND_MODULE_LOAD &modLoad) {
    std::string modulePath;

    if (!state->mem()->readString(modLoad.module_path, modulePath)) {
        getWarningsStream(state) << "could not read module path\n";
        return;
    }

    auto moduleName = std::string(llvm::sys::path::filename(modulePath));

    std::vector<SectionDescriptor> sections;
    if (!loadSections<S2E_LINUXMON_PHDR_DESC>(state, modLoad.phdr, modLoad.phdr_size, sections)) {
        return;
    }

    auto module =
        ModuleDescriptor::get(modulePath, moduleName, pid, state->regs()->getPageDir(), modLoad.entry_point, sections);

    getDebugStream(state) << module << '\n';

    onModuleLoad.emit(state, module);
}

void BaseLinuxMonitor::loadKernelImage(S2EExecutionState *state, uint64_t kernelStart) {
    ModuleDescriptor vmlinux;
    std::string kernelName = "vmlinux";

    getDebugStream(state) << "Kernel is at address " << hexval(kernelStart) << "\n";

    auto exe = m_vmi->getFromDisk("", kernelName, false);
    if (!exe) {
        getWarningsStream(state) << "Could not load vmlinux from disk\n";
        return;
    }

    std::vector<SectionDescriptor> sections;
    for (const auto &s : exe->getSections()) {
        if (!s.loadable) {
            continue;
        }

        // XXX: assume native load base == runtime load base?
        SectionDescriptor sd;
        sd.readable = s.readable;
        sd.writable = s.writable;
        sd.executable = s.executable;
        sd.size = s.size;
        sd.nativeLoadBase = s.start;
        sd.runtimeLoadBase = s.start;
        sections.push_back(sd);
    }

    vmlinux = ModuleDescriptor::get(kernelName, kernelName, 0, 0, 0, sections);

    onModuleLoad.emit(state, vmlinux);
}
} // namespace plugins
} // namespace s2e
