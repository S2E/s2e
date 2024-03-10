///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

//#define DEBUG_DPC

#include <s2e/ConfigFile.h>
#include <s2e/FastReg.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <vmi/FileProvider.h>
#include <vmi/PEFile.h>
#include <vmi/ntddk.h>

#include <llvm/ADT/DenseMap.h>

#include <stack>

#include "WindowsMonitor.h"

using namespace vmi::windows;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(WindowsMonitor, "Advanced Windows event monitoring plugin", "OSMonitor", "Vmi");

class WindowsMonitorState : public PluginState {
    friend class WindowsMonitor;

public:
    /* Maps a handle to a pid */
    typedef llvm::DenseMap<uint64_t, uint64_t> ProcessHandles;

    /* Tracks the set of open handles for all processes (identified by pid) */
    typedef llvm::DenseMap<uint64_t, ProcessHandles> HandlesMap;

    struct ProcInfo {
        uint64_t eprocess;
        uint64_t parentPid;

        ProcInfo() : eprocess(-1), parentPid(-1) {
        }
    };

    /* Maps a pid to an eprocess pointer */
    typedef llvm::DenseMap<uint64_t, ProcInfo> ProcessPids;

private:
    HandlesMap m_handles;
    ProcessPids m_pids;

    uint64_t m_cachedPid;
    uint64_t m_cachedTid;
    uint64_t m_cachedEthread;
    uint64_t m_cachedEprocess;

public:
    void addProcessHandle(uint64_t ownerPid, uint64_t handle, uint64_t targetPid) {
        m_handles[ownerPid][handle] = targetPid;
    }

    void removeHandles(uint64_t ownerPid) {
        HandlesMap::iterator it = m_handles.find(ownerPid);
        if (it != m_handles.end()) {
            m_handles.erase(it);
        }
    }

    bool getPidFromHandle(uint64_t ownerPid, uint64_t handle, uint64_t *pid) const {
        if (handle == (uint64_t) -1) {
            *pid = ownerPid;
            return true;
        }

        HandlesMap::const_iterator it = m_handles.find(ownerPid);
        if (it == m_handles.end()) {
            return false;
        }
        ProcessHandles::const_iterator it2 = (*it).second.find(handle);
        if (it2 == (*it).second.end()) {
            return false;
        }
        *pid = (*it2).second;
        return true;
    }

    void addProcess(uint64_t pid, uint64_t parentPid, uint64_t eprocess) {
        ProcInfo pi;
        pi.eprocess = eprocess;
        pi.parentPid = parentPid;
        m_pids[pid] = pi;
    }

    void removeProcess(uint64_t pid) {
        m_pids.erase(pid);
    }

    ProcInfo getProcess(uint64_t pid) const {
        ProcessPids::const_iterator it = m_pids.find(pid);
        if (it == m_pids.end()) {
            return ProcInfo();
        }
        return (*it).second;
    }

    virtual WindowsMonitorState *clone() const {
        return new WindowsMonitorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new WindowsMonitorState();
    }
};

static inline std::string GetFileName(const std::string path) {
    // Only keep the file name of the module
    std::string fileName;
    fileName = path;

    char seps[] = "/\\";
    for (unsigned i = 0; i < 2; ++i) {
        size_t pos = fileName.rfind(seps[i]);
        if (pos != std::string::npos) {
            fileName = fileName.substr(pos + 1);
        }
    }

    return fileName;
}

static inline std::string GetStrippedPath(const std::string &path) {
    return Vmi::stripWindowsModulePath(path);
}

// Windows may use arbitrary paths for module load/unload events
// (e.g., a short name like progra~1 instead of "program files").
// WindowsMonitor and all plugins always want to use the normalized path.
// s2e.sys intercepts every file access, checks if file path is normalized,
// and if not, sends to WindowsMonitor the normalized version, which the
// plugin keeps here in a map.
std::string WindowsMonitor::GetNormalizedPath(const std::string &path) {
    std::string str = GetStrippedPath(path);

    llvm::StringMap<std::string>::iterator it = m_normalizedNames.find(str);
    if (it != m_normalizedNames.end()) {
        return (*it).second;
    }
    return str;
}

void WindowsMonitor::NormalizePath(const std::string &path, std::string &normalizedPath,
                                   std::string &normalizedFileName) {
    normalizedPath = GetNormalizedPath(path);
    normalizedFileName = GetFileName(path);

    // Sometimes we don't know where the module is, especially if the windows api
    // did not provide the full path of the binary. Vmi will try its best to
    // locate the file.
    if (normalizedFileName == normalizedPath) {
        normalizedPath = "";
    }

    // We always want the module name to be lower case on windows. This simplifies configuration
    // of all the plugins that rely on the module name (e.g., ModuleExecutionDetector).
    // Windows tends to use different cases depending on the context, which would cause config to break.
    std::transform(normalizedFileName.begin(), normalizedFileName.end(), normalizedFileName.begin(), ::tolower);

    // Don't lower-case the full path for now. Plugins will do it themselves if needed
    // (e.g., Vmi will try to lookup the original path, and if failed, lower case it).
    // std::transform(normalizedPath.begin(), normalizedPath.end(), normalizedPath.begin(), ::tolower);
}

void WindowsMonitor::initialize() {
    m_kernelStart = 0;

    // Optional plugins for debugging
    m_tbTracer = s2e()->getPlugin<TranslationBlockTracer>();
    m_memTracer = s2e()->getPlugin<MemoryTracer>();

    m_vmi = s2e()->getPlugin<Vmi>();

    ConfigFile *cfg = s2e()->getConfig();
    m_debugDpc = cfg->getBool(getConfigKey() + ".debugDpc");
    m_debugAccessFault = cfg->getBool(getConfigKey() + ".debugAccessFault");

    clearCache();
}

void WindowsMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc) {
    if (pc == m_kernel.UnloadDriverPc - m_kernel.KernelNativeBase + m_kernel.KernelLoadBase) {
        signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onDriverUnload));
    } else if (m_kernel.PerfLogImageUnload && (pc == m_kernel.PerfLogImageUnload)) {
        signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onPerfLogImageUnload));
    }
}

void WindowsMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                         uint64_t endPc, bool staticTarget, uint64_t targetPc) {
    /* Driver load is always a call instruction */
    if (endPc == m_kernel.LoadDriverPc - m_kernel.KernelNativeBase + m_kernel.KernelLoadBase) {
        signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onDriverLoad));
    } else if (m_debugDpc && m_kernel.KiRetireDpcCallSite && (endPc == m_kernel.KiRetireDpcCallSite)) {
        signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onKiRetireDpcCallSite));
    }
}

std::shared_ptr<vmi::PEFile> WindowsMonitor::getFromDiskOrMemory(S2EExecutionState *state,
                                                                 const std::string &modulePath,
                                                                 const std::string &moduleName, uint64_t loadBase) {
    // Use locally-stored files first
    auto pe = m_vmi->getFromDisk(modulePath, moduleName, true);
    if (pe) {
        return std::dynamic_pointer_cast<vmi::PEFile>(pe);
    }

    auto file = vmi::GuestMemoryFileProvider::get(state, &Vmi::readGuestVirtual, nullptr, moduleName);
    return vmi::PEFile::get(file, true, loadBase);
}

template <typename UNICODE_STRING>
bool WindowsMonitor::getDriver(S2EExecutionState *state, uint64_t expectedSize, uint64_t expectedEntryPoint,
                               const UNICODE_STRING &nameOrPath, uint64_t baseAddress, ModuleDescriptor &desc) {
    // TODO: figure out full path of the driver
    std::string driverName;
    state->mem()->readUnicodeString(nameOrPath.Buffer, driverName, nameOrPath.Length);

    std::string normalizedPath, normalizedFileName;
    NormalizePath(driverName, normalizedPath, normalizedFileName);

    auto exec = getFromDiskOrMemory(state, normalizedPath, normalizedFileName, baseAddress);
    if (!exec) {
        getDebugStream(state) << "could not compute image data for " << driverName << "\n";
        return false;
    }

    desc = ModuleDescriptor::get(*exec.get(), 0, 0, normalizedFileName, normalizedPath, baseAddress);

    if (desc.Size != expectedSize) {
        getWarningsStream(state) << "Driver size mismatch for " << driverName << "\n";
    }

    if (desc.EntryPoint != expectedEntryPoint) {
        getWarningsStream(state) << "Driver entry point mismatch for " << driverName << "\n";
    }

    return true;
}

template <typename DRIVER_OBJECT, typename MODULE_ENTRY>
bool WindowsMonitor::readDriverDescriptor(S2EExecutionState *state, uint64_t pDriverDesc,
                                          ModuleDescriptor &DriverDesc) {
    /* TODO: retrieve the driver descriptor */
    DRIVER_OBJECT DriverObject;
    if (!state->mem()->read(pDriverDesc, &DriverObject, sizeof(DriverObject))) {
        getDebugStream(state) << "could not read driver descriptor " << hexval(pDriverDesc) << "\n";
        return false;
    }

    MODULE_ENTRY ModuleEntry;
    if (!state->mem()->read(DriverObject.DriverSection, &ModuleEntry, sizeof(ModuleEntry))) {
        getDebugStream(state) << "could not read driver module entry " << hexval(DriverObject.DriverSection) << "\n";
        return false;
    }

    return getDriver(state, DriverObject.DriverSize, DriverObject.DriverStart, ModuleEntry.DriverPath,
                     DriverObject.DriverStart, DriverDesc);
}

bool WindowsMonitor::readDriverDescriptorFromParameter(S2EExecutionState *state, ModuleDescriptor &DriverDesc) {
    if (state->getPointerSize() == 8) {
        uint64_t pDriverDesc = 0;
        pDriverDesc = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
        if (!readDriverDescriptor<DRIVER_OBJECT64, MODULE_ENTRY64>(state, pDriverDesc, DriverDesc)) {
            return false;
        }
    } else {
        uint32_t pDriverDesc = 0;
        OSMonitor::readConcreteParameter<uint32_t>(state, 0, &pDriverDesc);
        if (!readDriverDescriptor<DRIVER_OBJECT32, MODULE_ENTRY32>(state, pDriverDesc, DriverDesc)) {
            return false;
        }
    }

    return true;
}

void WindowsMonitor::onDriverLoad(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "detected driver load\n";

    ModuleDescriptor DriverDesc;
    if (!readDriverDescriptorFromParameter(state, DriverDesc)) {
        return;
    }

    /* Load the imported drivers too */
    vmi::Imports imports;
    if (m_vmi->getResolvedImports(state, DriverDesc, imports)) {
        StringSet importedModules;
        foreach2 (it, imports.begin(), imports.end()) {
            importedModules.insert((*it).first);
        }

        ModuleList modules;
        readModuleList(state, modules, importedModules);

        foreach2 (it, modules.begin(), modules.end()) {
            ModuleDescriptor &DriverDesc = *it;
            getDebugStream(state) << "[IMPORTED] " << DriverDesc << "\n";

            // The clients are supposed to filter duplicated load events
            onModuleLoad.emit(state, DriverDesc);
        }
    }

    getDebugStream(state) << DriverDesc << "\n";

    onModuleLoad.emit(state, DriverDesc);

    /* TODO: redirect the driver call to a custom function */
    if (m_kernel.LoadDriverHook) {
        /* ... */
    }
}

template <typename LIST_ENTRY, typename MODULE_ENTRY, typename POINTER>
bool WindowsMonitor::readModuleListGeneric(S2EExecutionState *state, ModuleList &modules, const StringSet &filter) {
    POINTER pListHead, pItem, pModuleEntry;
    LIST_ENTRY ListHead;
    MODULE_ENTRY ModuleEntry;

    pListHead = m_kernel.PsLoadedModuleList;
    if (!state->mem()->read(m_kernel.PsLoadedModuleList, &ListHead, sizeof(ListHead))) {
        return false;
    }

    for (pItem = ListHead.Flink; pItem != pListHead;) {
        pModuleEntry = pItem;

        if (state->mem()->read(pModuleEntry, &ModuleEntry, sizeof(ModuleEntry)) < 0) {
            getDebugStream(state) << "Could not load MODULE_ENTRY\n";
            return false;
        }

        ModuleDescriptor desc;

        if (!getDriver(state, ModuleEntry.ImageSize, ModuleEntry.EntryPoint, ModuleEntry.DriverPath,
                       ModuleEntry.BaseAddress, desc)) {
            getWarningsStream(state) << "Could not read driver module info\n";
            return false;
        }

        if (filter.empty() || (filter.find(desc.Name) != filter.end())) {
            modules.push_back(desc);
        }

        pItem = ListHead.Flink;
        if (!state->mem()->read(ListHead.Flink, &ListHead, sizeof(ListHead))) {
            return false;
        }
    }

    return true;
}

bool WindowsMonitor::readModuleList(S2EExecutionState *state, ModuleList &modules, const StringSet &filter) {
    if (state->getPointerSize() == 8) {
        return readModuleListGeneric<LIST_ENTRY64, MODULE_ENTRY64, uint64_t>(state, modules, filter);
    } else {
        return readModuleListGeneric<LIST_ENTRY32, MODULE_ENTRY32, uint32_t>(state, modules, filter);
    }
}

/* KiRetireDpc called the dpc about to invoke the DPC handler */
void WindowsMonitor::onKiRetireDpcCallSite(S2EExecutionState *state, uint64_t pc) {
#ifdef DEBUG_DPC
    // XXX: assumes 64-bits win7
    target_ulong Dpc = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
    target_ulong DeferredContext = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDX]));
    target_ulong SystemArgument1 = state->regs()->read<target_ulong>(CPU_OFFSET(regs[8]));
    target_ulong SystemArgument2 = state->regs()->read<target_ulong>(CPU_OFFSET(regs[9]));

    getDebugStream(state) << "DPC invoked: "
                          << " pc=" << hexval(state->regs()->getPc()) << " Dpc=" << hexval(Dpc)
                          << " DeferredContext=" << hexval(DeferredContext)
                          << " SystemArgument1=" << hexval(SystemArgument1)
                          << " SystemArgument2=" << hexval(SystemArgument2) << "\n";

    if (SystemArgument1 || SystemArgument2) {
        // These are usually nullptr, except when patchguard's DPC is called.
        // Could skip the DPC.

        bool tracing = false;
        if (m_memTracer && !m_memTracer->tracingEnabled()) {
            m_memTracer->connectMemoryTracing();
            tracing = true;
        }

        if (m_tbTracer && !m_tbTracer->tracingEnabled()) {
            m_tbTracer->enableTracing();
            tracing = true;
        }

        if (tracing) {
            // Ensure we get precise tracing the next time
            tb_flush(env);
            throw CpuExitException();
        }
    }
#endif
}

/* PerfLogImageUnload */
void WindowsMonitor::onPerfLogImageUnload(S2EExecutionState *state, uint64_t pc) {
    if (state->getPointerSize() == 8) {
        unloadModule<vmi::windows::UNICODE_STRING64>(state);
    } else {
        unloadModule<vmi::windows::UNICODE_STRING32>(state);
    }
}

template <typename UNICODE_STRING> void WindowsMonitor::unloadModule(S2EExecutionState *state) {
    target_ulong pName = 0, pid = 0, base = 0, size = 0;
    uint64_t pointerSize = state->getPointerSize();

    switch (m_kernel.KernelMajorVersion) {
        case 6: {
            switch (m_kernel.KernelMinorVersion) {
                case 3:   /* Windows 8.1 */
                case 2: { /* Windows 8 */
                    assert(pointerSize == 8);

                    pName = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
                    // unknown = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDX]));
                    pid = state->regs()->read<target_ulong>(CPU_OFFSET(regs[8]));
                    base = state->regs()->read<target_ulong>(CPU_OFFSET(regs[9]));

                    if (!state->mem()->read(state->regs()->getSp() + (1 + 4) * pointerSize, &size, pointerSize)) {
                        s2e()->getExecutor()->terminateState(*state, "WindowsMonitor: could not read stack");
                    }
                } break;

                case 1: { /* Windows 7 */
                    if (pointerSize == 8) {
                        /* Microsoft x64 */
                        pName = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
                        pid = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDX]));
                        base = state->regs()->read<target_ulong>(CPU_OFFSET(regs[8]));
                        size = state->regs()->read<target_ulong>(CPU_OFFSET(regs[9]));
                    } else {
                        /* Microsoft fastcall */
                        size = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
                        pName = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDX]));

                        if (!state->mem()->read(state->regs()->getSp() + 1 * pointerSize, &pid, pointerSize)) {
                            s2e()->getExecutor()->terminateState(*state, "WindowsMonitor: could not read stack");
                        }
                        if (!state->mem()->read(state->regs()->getSp() + 2 * pointerSize, &base, pointerSize)) {
                            s2e()->getExecutor()->terminateState(*state, "WindowsMonitor: could not read stack");
                        }
                    }
                } break;

                default:
                    s2e()->getExecutor()->terminateState(*state,
                                                         "WindowsMonitor: unsupported OS for onPerfLogImageUnload");
            }
        } break;

        case 10: { /* Windows 10 */
            assert(pointerSize == 8);

            pName = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));
            // unknown = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDX]));
            pid = state->regs()->read<target_ulong>(CPU_OFFSET(regs[8]));
            base = state->regs()->read<target_ulong>(CPU_OFFSET(regs[9]));

            if (!state->mem()->read(state->regs()->getSp() + (1 + 4) * pointerSize, &size, pointerSize)) {
                s2e()->getExecutor()->terminateState(*state, "WindowsMonitor: could not read stack");
            }
        } break;

        default: {
            s2e()->getExecutor()->terminateState(*state, "WindowsMonitor: unsupported OS for onPerfLogImageUnload");
            break;
        }
    }

    UNICODE_STRING unicodeName;
    if (!state->mem()->read(pName, &unicodeName, sizeof(unicodeName))) {
        getWarningsStream(state) << "WindowsMonitor::onPerfLogImageUnload "
                                 << " could not read module name\n";
        return;
    }

    std::string path, normalizedPath, normalizedName;
    if (!state->mem()->readUnicodeString(unicodeName.Buffer, path, unicodeName.Length / 2)) {
        getWarningsStream(state) << "WindowsMonitor::onPerfLogImageUnload "
                                 << " could not read module name\n";
        return;
    }

    NormalizePath(path, normalizedPath, normalizedName);

    auto exec = getFromDiskOrMemory(state, normalizedPath, normalizedName, base);
    if (!exec) {
        getWarningsStream(state) << "WindowsMonitor::onPerfLogImageUnload "
                                 << " could not get module " << path << "\n";
        return;
    }

    auto addressSpace = 0L;
    auto modulePid = 0L;

    if (!isKernelAddress(base)) {
        addressSpace = state->regs()->getPageDir();
        modulePid = pid;
    }

    auto module = ModuleDescriptor::get(*exec.get(), addressSpace, modulePid, normalizedName, normalizedPath, base);

    getDebugStream(state) << "onPerfLogImageUnload " << module << "\n";

    // Note: module unload may be triggered twice for device drivers,
    // the first time in IopDeleteDriver and the 2nd time here.
    onModuleUnload.emit(state, module);
}

/* IopDeleteDriver */
void WindowsMonitor::onDriverUnload(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "onDriverUnload: detected driver unload\n";

    ModuleDescriptor DriverDesc;

    if (!readDriverDescriptorFromParameter(state, DriverDesc)) {
        return;
    }

    getDebugStream(state) << "onDriverUnload: " << DriverDesc << "\n";

    onModuleUnload.emit(state, DriverDesc);
}

void WindowsMonitor::enableInstrumentation(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &WindowsMonitor::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &WindowsMonitor::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onPageDirectoryChange.connect(sigc::mem_fun(*this, &WindowsMonitor::onPageDirectoryChange));

    s2e()->getCorePlugin()->onPrivilegeChange.connect(sigc::mem_fun(*this, &WindowsMonitor::onPrivilegeChange));

    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &WindowsMonitor::onStateSwitch));

    /* This is for syscall monitoring */
    s2e()->getCorePlugin()->onTranslateSoftInterruptStart.connect(
        sigc::mem_fun(*this, &WindowsMonitor::onTranslateSoftInterruptStart));

    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
        sigc::mem_fun(*this, &WindowsMonitor::onTranslateSpecialInstructionEnd));
}

void WindowsMonitor::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                      TranslationBlock *tb, uint64_t pc,
                                                      enum special_instruction_t type,
                                                      const special_instruction_data_t *data) {
    if (type != SYSENTER && type != SYSCALL) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onSyscallInst));
}

void WindowsMonitor::onTranslateSoftInterruptStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc, unsigned vector) {
    if (vector != 0x2e) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &WindowsMonitor::onSyscallInt));
}

void WindowsMonitor::onSyscallInst(S2EExecutionState *state, uint64_t pc) {
    target_ulong syscallid = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EAX]));
    target_ulong stack = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ECX]));

    processSyscall(state, pc, syscallid, stack);
}

void WindowsMonitor::onSyscallInt(S2EExecutionState *state, uint64_t pc) {
    target_ulong syscallid = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EAX]));
    target_ulong stack = state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ESP]));

    processSyscall(state, pc, syscallid, stack);
}

/* Do the translation to actual syscall here */
void WindowsMonitor::processSyscall(S2EExecutionState *state, uint64_t pc, uint64_t syscallId, uint64_t stack) {
    onSyscall.emit(state, pc, syscallId, stack);
}

void WindowsMonitor::onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState) {
    DECLARE_PLUGINSTATE(WindowsMonitorState, nextState);
    m_cachedState = nextState;

    m_cachedPid = plgState->m_cachedPid;
    m_cachedTid = plgState->m_cachedTid;
    m_cachedEprocess = plgState->m_cachedEprocess;
    m_cachedEthread = plgState->m_cachedEthread;
}

bool WindowsMonitor::checkNewProcess(S2EExecutionState *state, bool fireEvent) {
    uint64_t prevProcess = 0, prevThread = 0;

    if (fireEvent) {
        // XXX: the check shouldn't be necessary
        // XXX: are pid=0 and tid=0 actually valid???
        prevProcess = getCurrentProcessId(state);
        prevThread = getCurrentThreadId(state);
    }

    bool ret = initCurrentProcessThreadId(state);
    if (!ret) {
        s2e_flush_output_streams();
        abort();
    }

    if (fireEvent) {
        uint64_t newProcess = getCurrentProcessId(state);
        uint64_t newThread = getCurrentThreadId(state);

        if (newProcess != prevProcess || newThread != prevThread) {
            onProcessOrThreadSwitch.emit(state);
        }
    }

    return ret;
}

void WindowsMonitor::onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current) {
    /**
     * Hopefully, this will ensure the consistency of the cache.
     * Thread switches must go through a privilege change.
     */

    bool ret = checkNewProcess(state, true);
    assert(ret);
}

void WindowsMonitor::onPageDirectoryChange(S2EExecutionState *state, uint64_t previous, uint64_t current) {
    /**
     * This should ensure that the next call to getCurrentThreadId
     * and getCurrentProcessId return fresh results.
     * XXX: this might be redundant with onPrivilegeChange
     */
    bool ret = checkNewProcess(state, true);
    assert(ret);
}

void WindowsMonitor::opcodeInitKernelStructs(S2EExecutionState *state, uint64_t guestDataPtr,
                                             const S2E_WINMON2_COMMAND &command) {
    m_kernel = command.Structs;

    getDebugStream(state) << "initializing kernel data structures\n"
                          << " KernelNativeBase: " << hexval(m_kernel.KernelNativeBase) << "\n"
                          << " KernelLoadBase: " << hexval(m_kernel.KernelLoadBase) << "\n"
                          << " Version: " << m_kernel.KernelMajorVersion << '.' << m_kernel.KernelMinorVersion << "."
                          << m_kernel.KernelBuildNumber << "\n"
                          << " KernelChecksum: " << hexval(m_kernel.KernelChecksum) << "\n"
                          << " LoadDriverPc: " << hexval(m_kernel.LoadDriverPc) << "\n"
                          << " UnloadDriverPc: " << hexval(m_kernel.UnloadDriverPc) << "\n"
                          << " LoadDriverHook: " << hexval(m_kernel.LoadDriverHook) << "\n"
                          << " PointerSizeInBytes: " << hexval(m_kernel.PointerSizeInBytes) << "\n"
                          << " KeBugCheckEx: " << hexval(m_kernel.KeBugCheckEx) << "\n"
                          << " BugCheckHook: " << hexval(m_kernel.BugCheckHook) << "\n"
                          << " KPCR: " << hexval(m_kernel.KPCR) << "\n"
                          << " KPRCB: " << hexval(m_kernel.KPRCB) << "\n"
                          << " PsLoadedModuleList: " << hexval(m_kernel.PsLoadedModuleList) << "\n"
                          << " PerfLogImageUnload: " << hexval(m_kernel.PerfLogImageUnload) << "\n";

    if (!m_kernel.KernelLoadBase) {
        getDebugStream(state) << "invalid kernel load base\n";
        exit(-1);
    }

    if (!m_kernel.PerfLogImageUnload) {
        getDebugStream(state) << "PerfLogImageUnload is null, module unloads partially supported.\n";
    }

    if (m_kernel.EThreadSegment != R_FS && m_kernel.EThreadSegment != R_GS) {
        getDebugStream(state) << "Invalid ETHREAD segment register " << m_kernel.EThreadSegment << "\n";
        exit(-1);
    }

    if (!m_kernel.EThreadProcessOffset) {
        getDebugStream(state) << "Invalid EThreadProcessOffset";
        exit(-1);
    }

    if (!m_kernel.PsLoadedModuleList) {
        getDebugStream(state) << "Invalid PsLoadedModuleList\n";
        exit(-1);
    }

    if (!m_kernel.EProcessUniqueIdOffset) {
        getDebugStream(state) << "Invalid EProcessUniqueIdOffset";
        exit(-1);
    }

    if (m_kernel.PointerSizeInBytes == 8) {
        m_kernelStart = 0x8000000000000000;
    } else {
        // XXX: this may be 0xc0000000 with the 3gb switch
        m_kernelStart = 0x80000000;
    }

    /* Fetch the version block */
    if (m_kernel.KdVersionBlock) {
        if (!state->mem()->read(m_kernel.KdVersionBlock, &m_versionBlock, sizeof(m_versionBlock))) {
            getWarningsStream(state) << "could not read the DBGKD_GET_VERSION64 structure\n";
            exit(-1);
        }

        getDebugStream(state) << "DBGKD_GET_VERSION64\n"
                              << "MajorVersion: " << hexval(m_versionBlock.MajorVersion) << "\n"
                              << "MinorVersion: " << hexval(m_versionBlock.MinorVersion) << "\n"
                              << "ProtocolVersion: " << hexval(m_versionBlock.ProtocolVersion) << "\n"
                              << "KdSecondaryVersion: " << hexval(m_versionBlock.KdSecondaryVersion) << "\n"
                              << "KernBase: " << hexval(m_versionBlock.KernBase) << "\n"
                              << "PsLoadedModuleList: " << hexval(m_versionBlock.PsLoadedModuleList) << "\n";
    }

    {
        if (!initCurrentProcessThreadId(state)) {
            getDebugStream(state) << "Could not initialize initial thread and process info\n";
            exit(-1);
        }

        /* Display stack info for debugging */
        uint64_t pEThread = getCurrentThread(state);
        uint64_t stackBase, stackLimit;
        getCurrentStack(state, &stackBase, &stackLimit);
        getDebugStream(state) << "ETHREAD " << hexval(pEThread) << " StackBase: " << hexval(stackBase)
                              << " StackLimit: " << hexval(stackLimit) << " ESP: " << hexval(state->regs()->getSp())
                              << "\n";

        uint64_t DPCStackBottom = 0, DPCStackSize = 0;
        if (!getDpcStack(state, &DPCStackBottom, &DPCStackSize)) {
            getWarningsStream(state) << "could not read the DPC stack address\n";
            exit(-1);
        }

        getDebugStream(state) << " DPCStackBase: " << hexval(DPCStackBottom)
                              << " DPCStackSize: " << hexval(DPCStackSize) << "\n";
    }

    enableInstrumentation(state);

    completeInitialization(state);

    bool ret = checkNewProcess(state, true);
    if (!ret) {
        getWarningsStream(state) << "Cannot init initial process\n";
        exit(-1);
    }

    return;
}

bool WindowsMonitor::getModuleDescriptorFromCommand(S2EExecutionState *state, const S2E_WINMON2_COMMAND &command,
                                                    ModuleDescriptor &module) {

    auto pid = 0L;
    auto addressSpace = 0L;
    auto loadBase = command.Module2.LoadBase;
    auto size = command.Module2.Size;

    if (isKernelAddress(module.LoadBase)) {
        pid = 0;
        addressSpace = 0;
    } else {
        pid = command.Module2.Pid;
        addressSpace = state->regs()->getPageDir();
    }

    std::string path;
    uint64_t characters = command.Module2.UnicodeModulePathSizeInBytes / sizeof(uint16_t);
    if (!state->mem()->readUnicodeString(command.Module2.UnicodeModulePath, path, characters)) {
        getWarningsStream(state) << "could not read module name\n";
        return false;
    }

    std::string normalizedName, normalizedPath;
    NormalizePath(path, normalizedPath, normalizedName);

    auto exec = getFromDiskOrMemory(state, normalizedPath, normalizedName, loadBase);
    if (!exec) {
        getWarningsStream(state) << "could not initialize module information\n";
        return false;
    }

    module = ModuleDescriptor::get(*exec.get(), addressSpace, pid, normalizedName, normalizedPath, loadBase);
    if (exec->getImageSize() != size) {
        getWarningsStream(state) << "Size mismatch for " << normalizedName << "\n";
    }

    return true;
}

void WindowsMonitor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_WINMON2_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_HOOK_PLUGIN_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case INIT_KERNEL_STRUCTS: {
            opcodeInitKernelStructs(state, guestDataPtr, command);

            // Make sure the guest code gets instrumented the next time
            tb_flush(env);
            state->regs()->setPc(state->regs()->getPc() + OPCODE_SIZE);
            throw CpuExitException();
        } break;

        case LOAD_DRIVER: {
            ModuleDescriptor module;
            if (getModuleDescriptorFromCommand(state, command, module)) {
                getDebugStream(state) << "onDriverLoad " << module << "\n";
                onModuleLoad.emit(state, module);
            }
        } break;

        case UNLOAD_DRIVER: {
            ModuleDescriptor module;
            if (getModuleDescriptorFromCommand(state, command, module)) {
                getDebugStream(state) << "onDriverUnload " << module << "\n";
                onModuleUnload.emit(state, module);
            }
        } break;

        case THREAD_CREATE: {
            getDebugStream(state) << "creating thread " << hexval(command.Thread.EThread) << "\n";

            ThreadDescriptor desc;
            desc.KernelMode = true;
            desc.Pid = command.Thread.ProcessId;
            desc.Tid = command.Thread.ThreadId;
            if (getKernelStack(state, command.Thread.EThread, &desc.KernelStackBottom, &desc.KernelStackSize)) {
                onThreadCreate.emit(state, desc);
            }
        } break;

        case THREAD_EXIT: {
            getDebugStream(state) << "destroying thread " << hexval(command.Thread.EThread) << "\n";

            ThreadDescriptor desc;
            desc.KernelMode = true;
            desc.Pid = command.Thread.ProcessId;
            desc.Tid = command.Thread.ThreadId;
            if (getKernelStack(state, command.Thread.EThread, &desc.KernelStackBottom, &desc.KernelStackSize)) {
                onThreadExit.emit(state, desc);
            }
        } break;

        case LOAD_IMAGE: {
            ModuleDescriptor module;
            if (getModuleDescriptorFromCommand(state, command, module)) {
                getDebugStream(state) << "onModuleLoad " << module << "\n";
                onModuleLoad.emit(state, module);
            }
        } break;

        case LOAD_PROCESS: {
            DECLARE_PLUGINSTATE(WindowsMonitorState, state);
            target_ulong cr3 = state->regs()->getPageDir();
            plgState->addProcess(command.Process.ProcessId, command.Process.ParentProcessId, command.Process.EProcess);

            uint64_t characters = command.Process.UnicodeImagePathSizeInBytes / sizeof(uint16_t);
            std::string path, normalizedPath, fileName;
            if (!state->mem()->readUnicodeString(command.Process.UnicodeImagePath, path, characters)) {
                getWarningsStream(state) << "could not read process path\n";
                break;
            }

            NormalizePath(path, normalizedPath, fileName);

            getDebugStream(state) << "Process load " << normalizedPath << " (" << fileName << ")"
                                  << " pid=" << command.Process.ProcessId << "\n";

            onProcessLoad.emit(state, cr3, command.Process.ProcessId, fileName);
        } break;

        case UNLOAD_PROCESS: {
            uint64_t returnCode = 0;
            if (!state->mem()->read(command.Process.EProcess + m_kernel.EProcessExitStatusOffset, &returnCode,
                                    sizeof(uint64_t))) {
                getWarningsStream(state) << "could not read process return code\n";
            }

            DECLARE_PLUGINSTATE(WindowsMonitorState, state);

            getDebugStream(state) << "Process unload pid=" << hexval(command.Process.ProcessId) << "\n";

            plgState->removeHandles(command.Process.ProcessId);
            plgState->removeProcess(command.Process.ProcessId);
            target_ulong cr3 = state->regs()->getPageDir();

            onProcessUnload.emit(state, cr3, command.Process.ProcessId, returnCode);
        } break;

        case ACCESS_FAULT: {
            if (m_debugAccessFault) {
                getDebugStream(state) << "MmAccessFault "
                                      << " Address: " << hexval(command.AccessFault.Address)
                                      << " AccessMode: " << hexval(command.AccessFault.AccessMode)
                                      << " StatusCode: " << hexval(command.AccessFault.StatusCode)
                                      << " Pid: " << hexval(getCurrentProcessId(state)) << "\n";
            }

            onAccessFault.emit(state, command.AccessFault);
        } break;

        case PROCESS_HANDLE_CREATE: {
            DECLARE_PLUGINSTATE(WindowsMonitorState, state);

            plgState->addProcessHandle(command.ProcessHandle.SourceProcessId, command.ProcessHandle.Handle,
                                       command.ProcessHandle.TargetProcessId);
        } break;

        case ALLOCATE_VIRTUAL_MEMORY: {
            onNtAllocateVirtualMemory.emit(state, command.AllocateVirtualMemory);
        } break;

        case FREE_VIRTUAL_MEMORY: {
            onNtFreeVirtualMemory.emit(state, command.FreeVirtualMemory);
        } break;

        case PROTECT_VIRTUAL_MEMORY: {
            onNtProtectVirtualMemory.emit(state, command.ProtectVirtualMemory);
        } break;

        case MAP_VIEW_OF_SECTION: {
            onNtMapViewOfSection.emit(state, command.MapViewOfSection);
        } break;

        case UNMAP_VIEW_OF_SECTION: {
            onNtUnmapViewOfSection.emit(state, command.UnmapViewOfSection);
        } break;

        case STORE_NORMALIZED_NAME: {
            std::string OriginalName, NormalizedName;
            bool ok = true;
            ok &= state->mem()->readUnicodeString(command.NormalizedName.OriginalName, OriginalName,
                                                  command.NormalizedName.OriginalNameSizeInBytes / 2);

            ok &= state->mem()->readUnicodeString(command.NormalizedName.NormalizedName, NormalizedName,
                                                  command.NormalizedName.NormalizedNameSizeInBytes / 2);

            if (ok) {
                OriginalName = GetStrippedPath(OriginalName);
                NormalizedName = GetStrippedPath(NormalizedName);
                getDebugStream(state) << "OriginalName: " << OriginalName << " NormalizedName: " << NormalizedName
                                      << "\n";

                m_normalizedNames[OriginalName] = NormalizedName;
            }

        } break;

        default: {
            getWarningsStream(state) << "unknown command\n";
        } break;
    }
}

uint64_t WindowsMonitor::getTidReg(S2EExecutionState *state) {
    int reg = state->getPointerSize() == 4 ? R_FS : R_GS;
    return s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(segs[reg].base));
}

void WindowsMonitor::clearCache() {
    m_cachedPid = -1;
    m_cachedTid = -1;
    m_cachedEprocess = 0;
    m_cachedEthread = 0;
    m_cachedState = nullptr;
}

template <typename T>
static inline bool _ReadCurrentProcessThreadId(Plugin *plg, S2EExecutionState *state,
                                               const S2E_WINMON2_KERNEL_STRUCTS &k, uint64_t *pid, uint64_t *tid,
                                               uint64_t *_pkthread = nullptr, uint64_t *_pkprocess = nullptr) {
    T pkthread;
    if (!state->mem()->read(k.KPRCB + k.EThreadSegmentOffset, &pkthread, sizeof(pkthread))) {
        plg->getDebugStream() << "_ReadCurrentProcessThreadId: Could not read KPRCB "
                              << hexval(k.KPRCB + k.EThreadSegmentOffset) << "\n";
        return false;
    }

    struct {
        T UniqueProcess;
        T UniqueThread;
    } cid;

    if (!state->mem()->read(pkthread + k.EThreadCidOffset, &cid, sizeof(cid))) {
        plg->getDebugStream() << "_ReadCurrentProcessThreadId: Could not read thread CID "
                              << hexval(pkthread + k.EThreadCidOffset) << "\n";
        return false;
    }

    *pid = cid.UniqueProcess;
    *tid = cid.UniqueThread;

    if (_pkthread) {
        *_pkthread = pkthread;
    }

    if (_pkprocess) {
        T pkprocess;
        if (!state->mem()->read(pkthread + k.EThreadProcessOffset, &pkprocess, sizeof(pkprocess))) {
            plg->getDebugStream() << "_ReadCurrentProcessThreadId: Could not read thread pkprocess "
                                  << hexval(pkthread + k.EThreadProcessOffset) << "\n";
            return false;
        }
        *_pkprocess = pkprocess;
    }

    return true;
}

static inline bool ReadCurrentProcessThreadId(Plugin *plg, S2EExecutionState *state,
                                              const S2E_WINMON2_KERNEL_STRUCTS &k, uint64_t *pid, uint64_t *tid,
                                              uint64_t *_pkthread = nullptr, uint64_t *_pkprocess = nullptr) {
    if (k.PointerSizeInBytes == 8) {
        return _ReadCurrentProcessThreadId<uint64_t>(plg, state, k, pid, tid, _pkthread, _pkprocess);
    } else {
        return _ReadCurrentProcessThreadId<uint32_t>(plg, state, k, pid, tid, _pkthread, _pkprocess);
    }
}

bool WindowsMonitor::initCurrentProcessThreadId(S2EExecutionState *state) {
    uint64_t pid, tid, pkthread, pkprocess;
    if (!ReadCurrentProcessThreadId(this, state, m_kernel, &pid, &tid, &pkthread, &pkprocess)) {
        return false;
    }

    m_cachedPid = pid;
    m_cachedTid = tid;
    m_cachedState = state;
    m_cachedEthread = pkthread;
    m_cachedEprocess = pkprocess;

    DECLARE_PLUGINSTATE(WindowsMonitorState, state);
    plgState->m_cachedPid = pid;
    plgState->m_cachedTid = tid;
    plgState->m_cachedEthread = pkthread;
    plgState->m_cachedEprocess = pkprocess;

    return true;
}

bool WindowsMonitor::getKernelStack(S2EExecutionState *state, uint64_t pEThread, uint64_t *bottom, uint64_t *size) {
    uint64_t _base = 0;
    uint64_t _limit = 0;
    bool ok = true;
    unsigned ps = state->getPointerSize();
    ok &= state->mem()->read(pEThread + m_kernel.EThreadStackBaseOffset, &_base, ps);
    ok &= state->mem()->read(pEThread + m_kernel.EThreadStackLimitOffset, &_limit, ps);

    if (!ok) {
        return false;
    }

    if (size) {
        *size = _base - _limit;
    }

    if (bottom) {
        *bottom = _limit;
    }

    // TODO: handle DPC stack
    uint64_t sp = state->regs()->getSp();
    return sp >= *bottom && sp < (*bottom + *size);
}

bool WindowsMonitor::getDpcStack(S2EExecutionState *state, uint64_t *bottom, uint64_t *size) {
    bool ok = true;
    *bottom = 0;
    *size = 0;
    ok &= state->mem()->read(m_kernel.DPCStackBasePtr, bottom, state->getPointerSize());
    *size = m_kernel.DPCStackSize;
    return ok;
}

bool WindowsMonitor::getCurrentStack(S2EExecutionState *state, uint64_t *bottom, uint64_t *size) {
    // Check if we are on the DPC stack
    uint64_t DPCStackSize = 0, DPCStackBase = 0;
    if (getDpcStack(state, &DPCStackBase, &DPCStackSize)) {
        uint64_t sp = state->regs()->getSp();
        if (sp >= DPCStackBase && sp < (DPCStackBase + DPCStackSize)) {
            *bottom = DPCStackBase;
            *size = DPCStackSize;
            getDebugStream(state) << "We are on DPC stack\n";
            return true;
        }
    }

    // Works in kernel mode only
    uint64_t pEThread = getCurrentThread(state);
    if (!pEThread) {
        return false;
    }

    return getKernelStack(state, pEThread, bottom, size);
}

uint64_t WindowsMonitor::getPidFromHandle(S2EExecutionState *state, uint64_t ownerPid, uint64_t handle) const {
    DECLARE_PLUGINSTATE(WindowsMonitorState, state);
    uint64_t pid;
    if (!plgState->getPidFromHandle(ownerPid, handle, &pid)) {
        return 0;
    }
    return pid;
}

bool WindowsMonitor::getMemoryStatisticsForCurrentProcess(S2EExecutionState *state, MemoryInformation &info) {
    uint64_t peprocess = getCurrentProcess(state);

    bool ok = true;
    ok &= state->mem()->read(peprocess + m_kernel.EProcessCommitChargeOffset, &info.CommitCharge, sizeof(uint64_t));
    ok &= state->mem()->read(peprocess + m_kernel.EProcessVirtualSizeOffset, &info.VirtualSize, sizeof(uint64_t));
    ok &=
        state->mem()->read(peprocess + m_kernel.EProcessPeakVirtualSizeOffset, &info.PeakVirtualSize, sizeof(uint64_t));
    ok &= state->mem()->read(peprocess + m_kernel.EProcessCommitChargePeakOffset, &info.PeakCommitCharge,
                             sizeof(uint64_t));

    return ok;
}

bool WindowsMonitor::getVirtualMemoryInfo(S2EExecutionState *state, uint64_t Process, uint64_t Address,
                                          uint64_t *StartAddress, uint64_t *EndAddress, uint64_t *Protection) {
    if (!(m_kernel.KernelMajorVersion == 5 && m_kernel.KernelMinorVersion == 1)) {
        // TODO: make it work on other versions of Windows
        return false;
    }

    if (m_kernel.PointerSizeInBytes != 4) {
        return false;
    }

    uint64_t pVad = 0;

    if (!state->mem()->read(Process + m_kernel.EProcessVadRootOffset, &pVad, sizeof(uint32_t))) {
        return false;
    }

    /* Traverse the VAD tree */
    uint64_t pfn = Address >> 12;
    while (pVad) {
        MMVAD32_XP Vad;
        if (!state->mem()->read(pVad, &Vad, sizeof(MMVAD32_XP))) {
            return false;
        }

        if (pfn >= Vad.StartingVpn && pfn <= Vad.EndingVpn) {
            /* Found it ! */
            *StartAddress = Vad.StartingVpn << 12;
            *EndAddress = Vad.EndingVpn << 12;

            *Protection = 0;

            using namespace vmi::windows;
            switch (Vad.VadFlags.Protection) {
                case MM_READONLY:
                    *Protection = 0x4;
                    break;
                case MM_EXECUTE:
                    *Protection = 0x1;
                    break;
                case MM_EXECUTE_READ:
                    *Protection = 0x5;
                    break;
                case MM_READWRITE:
                    *Protection = 0x3;
                    break;
                case MM_WRITECOPY:
                    *Protection = 0x4;
                    break;
                case MM_EXECUTE_READWRITE:
                    *Protection = 0x7;
                    break;
                case MM_EXECUTE_WRITECOPY:
                    *Protection = 0x5;
                    break;
            }

            return true;
        } else if (pfn < Vad.StartingVpn) {
            pVad = Vad.Left;
        } else {
            pVad = Vad.Right;
        }
    }

    return false;
}

bool WindowsMonitor::dumpVad(S2EExecutionState *state) {
    if (m_kernel.KernelMajorVersion != 5 && m_kernel.KernelMinorVersion != 1) {
        // TODO: make it work on other versions of Windows
        return false;
    }

    if (m_kernel.PointerSizeInBytes != 4) {
        return false;
    }

    uint64_t Process = getCurrentProcess(state);
    uint64_t pVad = 0;

    getDebugStream(state) << "Dumping VAD tree for process " << getCurrentProcessId(state) << "\n";

    if (!state->mem()->read(Process + m_kernel.EProcessVadRootOffset, &pVad, sizeof(uint32_t))) {
        return false;
    }

    std::stack<uint64_t> parentStack;

    while (!parentStack.empty() || pVad) {
        if (pVad) {
            MMVAD32_XP Vad;
            if (!state->mem()->read(pVad, &Vad, sizeof(MMVAD32_XP))) {
                return false;
            }

            getDebugStream(state) << "VAD " << hexval(pVad) << " Start=" << hexval(Vad.StartingVpn * 0x1000)
                                  << " End=" << hexval(Vad.EndingVpn * 0x1000)
                                  << " CommitCharge=" << hexval(Vad.VadFlags.CommitCharge)
                                  << " Protection=" << hexval(Vad.VadFlags.Protection) << "\n";
            if (Vad.Right) {
                parentStack.push(Vad.Right);
            }

            pVad = Vad.Left;
        } else {
            pVad = parentStack.top();
            parentStack.pop();
        }
    }

    return true;
}

uint64_t WindowsMonitor::getProcess(S2EExecutionState *state, uint64_t pid) const {
    DECLARE_PLUGINSTATE_CONST(WindowsMonitorState, state);
    return plgState->getProcess(pid).eprocess;
}

uint64_t WindowsMonitor::getProcessParent(S2EExecutionState *state, uint64_t pid) const {
    DECLARE_PLUGINSTATE_CONST(WindowsMonitorState, state);
    return plgState->getProcess(pid).parentPid;
}

QDict *WindowsMonitor::getTrapInformation(S2EExecutionState *state, uint64_t trapInfo, uint64_t *pc, uint64_t *sp) {
    QDict *info = qdict_new();

    using namespace vmi::windows;
    if (state->getPointerSize() == 4) {
        KTRAP_FRAME32 TrapFrame;
        if (!state->mem()->read(trapInfo, &TrapFrame, sizeof(TrapFrame))) {
            return info;
        }

        qdict_put_obj(info, "eip", QOBJECT(qnum_from_int(TrapFrame.Eip)));
        qdict_put_obj(info, "eax", QOBJECT(qnum_from_int(TrapFrame.Eax)));
        qdict_put_obj(info, "ebx", QOBJECT(qnum_from_int(TrapFrame.Ebx)));
        qdict_put_obj(info, "ecx", QOBJECT(qnum_from_int(TrapFrame.Ecx)));
        qdict_put_obj(info, "edx", QOBJECT(qnum_from_int(TrapFrame.Edx)));
        qdict_put_obj(info, "edi", QOBJECT(qnum_from_int(TrapFrame.Edi)));
        qdict_put_obj(info, "esi", QOBJECT(qnum_from_int(TrapFrame.Esi)));
        qdict_put_obj(info, "ebp", QOBJECT(qnum_from_int(TrapFrame.Ebp)));
        qdict_put_obj(info, "esp", QOBJECT(qnum_from_int(TrapFrame.HardwareEsp)));

        *pc = TrapFrame.Eip;
        *sp = TrapFrame.HardwareEsp;

    } else {
        KTRAP_FRAME64 TrapFrame;
        if (!state->mem()->read(trapInfo, &TrapFrame, sizeof(TrapFrame))) {
            return info;
        }

        qdict_put_obj(info, "rip", QOBJECT(qnum_from_int(TrapFrame.Rip)));
        qdict_put_obj(info, "rax", QOBJECT(qnum_from_int(TrapFrame.Rax)));
        qdict_put_obj(info, "rbx", QOBJECT(qnum_from_int(TrapFrame.Rbx)));
        qdict_put_obj(info, "rcx", QOBJECT(qnum_from_int(TrapFrame.Rcx)));
        qdict_put_obj(info, "rdx", QOBJECT(qnum_from_int(TrapFrame.Rdx)));
        qdict_put_obj(info, "rdi", QOBJECT(qnum_from_int(TrapFrame.Rdi)));
        qdict_put_obj(info, "rsi", QOBJECT(qnum_from_int(TrapFrame.Rsi)));
        qdict_put_obj(info, "rbp", QOBJECT(qnum_from_int(TrapFrame.Rbp)));
        qdict_put_obj(info, "rsp", QOBJECT(qnum_from_int(TrapFrame.Rsp)));

        *pc = TrapFrame.Rip;
        *sp = TrapFrame.Rsp;
    }

    return info;
}

} // namespace plugins
} // namespace s2e
