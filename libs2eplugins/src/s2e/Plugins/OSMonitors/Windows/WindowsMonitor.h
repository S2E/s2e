///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_WINDOWSMONITOR2_H
#define S2E_PLUGINS_WINDOWSMONITOR2_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Events.h>
#include <s2e/Plugins/Core/Vmi.h>

#include <s2e/Plugins/ExecutionTracers/MemoryTracer.h>
#include <s2e/Plugins/ExecutionTracers/TranslationBlockTracer.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>

#include <vmi/ntddk.h>

#include <llvm/ADT/StringMap.h>

namespace s2e {
namespace plugins {

typedef enum S2E_WINMON2_COMMANDS {
    INIT_KERNEL_STRUCTS,
    LOAD_DRIVER,
    UNLOAD_DRIVER,
    THREAD_CREATE,
    THREAD_EXIT,
    LOAD_IMAGE,
    LOAD_PROCESS,
    UNLOAD_PROCESS,
    ACCESS_FAULT,
    PROCESS_HANDLE_CREATE,

    ALLOCATE_VIRTUAL_MEMORY,
    FREE_VIRTUAL_MEMORY,
    PROTECT_VIRTUAL_MEMORY,
    MAP_VIEW_OF_SECTION,
    UNMAP_VIEW_OF_SECTION,

    STORE_NORMALIZED_NAME
} S2E_WINMON2_COMMANDS;

typedef struct S2E_WINMON2_KERNEL_STRUCTS {
    uint64_t KernelNativeBase;
    uint64_t KernelLoadBase;
    uint64_t KernelChecksum;
    uint64_t KernelMajorVersion;
    uint64_t KernelMinorVersion;
    uint64_t KernelBuildNumber;

    uint64_t LoadDriverPc;
    uint64_t UnloadDriverPc;
    uint64_t LoadDriverHook;

    uint64_t PointerSizeInBytes;

    uint64_t KeBugCheckEx;
    uint64_t BugCheckHook;

    uint64_t KPCR;

    // The KPRCB is a struct at the end of the KPCR
    uint64_t KPRCB;

    uint64_t KdDebuggerDataBlock; // Address in the kernel file
    uint64_t KdVersionBlock;      // Stored in the KPCR

    /**
     * Index of the segment that contains the pointer
     * to the current thread.
     */
    uint64_t EThreadSegment; // R_FS / RG_S
    uint64_t EThreadSegmentOffset;
    uint64_t EThreadStackBaseOffset;
    uint64_t EThreadStackLimitOffset;
    uint64_t EThreadProcessOffset;
    uint64_t EThreadCidOffset;

    uint64_t EProcessUniqueIdOffset;
    uint64_t EProcessCommitChargeOffset;
    uint64_t EProcessVirtualSizeOffset;
    uint64_t EProcessPeakVirtualSizeOffset;
    uint64_t EProcessCommitChargePeakOffset;
    uint64_t EProcessVadRootOffset;
    uint64_t EProcessExitStatusOffset;

    uint64_t DPCStackBasePtr;
    uint64_t DPCStackSize;

    uint64_t PsLoadedModuleList;

    uint64_t PerfLogImageUnload;

    uint64_t KiRetireDpcCallSite;
} S2E_WINMON2_KERNEL_STRUCTS;

#define S2E_MODULE_MAX_LEN 255

typedef struct S2E_WINMON2_MODULE {
    uint64_t LoadBase;
    uint64_t Size;
    uint64_t FileNameOffset;
    uint8_t FullPathName[S2E_MODULE_MAX_LEN + 1];
} S2E_WINMON2_MODULE;

typedef struct S2E_WINMON2_MODULE2 {
    uint64_t LoadBase;
    uint64_t Size;
    uint64_t Pid;
    uint64_t UnicodeModulePath;
    uint64_t UnicodeModulePathSizeInBytes;
} S2E_WINMON2_MODULE2;

typedef struct S2E_WINMON2_ACCESS_FAULT {
    uint64_t Address;
    uint64_t AccessMode;
    uint64_t StatusCode;
    uint64_t TrapInformation;
    uint64_t ReturnAddress;
} S2E_WINMON2_ACCESS_FAULT;

typedef struct S2E_WINMON2_PROCESS_CREATION {
    uint64_t ProcessId;
    uint64_t ParentProcessId;
    uint64_t EProcess;
    uint64_t UnicodeImagePath;
    uint64_t UnicodeImagePathSizeInBytes;
} S2E_WINMON2_PROCESS_CREATION;

typedef struct S2E_WINMON2_THREAD_CREATION {
    uint64_t ProcessId;
    uint64_t ThreadId;
    uint64_t EThread;
} S2E_WINMON2_THREAD_CREATION;

typedef struct S2E_WINMON2_PROCESS_HANDLE_CREATION {
    /* The process that requested the handle */
    uint64_t SourceProcessId;

    /* The process that the handle is referencing */
    uint64_t TargetProcessId;

    /* The handle itself */
    uint64_t Handle;
} S2E_WINMON2_PROCESS_HANDLE_CREATION;

struct S2E_WINMON2_ALLOCATE_VM {
    uint64_t Status;
    uint64_t ProcessHandle;
    uint64_t BaseAddress;
    uint64_t Size;
    uint64_t AllocationType;
    uint64_t Protection;
};

struct S2E_WINMON2_FREE_VM {
    uint64_t Status;
    uint64_t ProcessHandle;
    uint64_t BaseAddress;
    uint64_t Size;
    uint64_t FreeType;
};

struct S2E_WINMON2_PROTECT_VM {
    uint64_t Status;
    uint64_t ProcessHandle;
    uint64_t BaseAddress;
    uint64_t Size;
    uint64_t NewProtection;
    uint64_t OldProtection;
};

struct S2E_WINMON2_MAP_SECTION {
    uint64_t Status;
    uint64_t ProcessHandle;
    uint64_t BaseAddress;
    uint64_t Size;
    uint64_t AllocationType;
    uint64_t Win32Protect;
};

struct S2E_WINMON2_UNMAP_SECTION {
    uint64_t Status;
    uint64_t EProcess;
    uint64_t Pid;
    uint64_t BaseAddress;
};

struct S2E_WINMON2_NORMALIZED_NAME {
    uint64_t OriginalName;
    uint64_t OriginalNameSizeInBytes;
    uint64_t NormalizedName;
    uint64_t NormalizedNameSizeInBytes;
};

enum S2E_WINMON2_PROTECTION {
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80
};

typedef struct S2E_WINMON2_COMMAND {
    S2E_WINMON2_COMMANDS Command;
    union {
        S2E_WINMON2_MODULE Module;
        S2E_WINMON2_MODULE2 Module2;
        S2E_WINMON2_KERNEL_STRUCTS Structs;
        S2E_WINMON2_ACCESS_FAULT AccessFault;
        S2E_WINMON2_THREAD_CREATION Thread;
        S2E_WINMON2_PROCESS_CREATION Process;
        S2E_WINMON2_PROCESS_HANDLE_CREATION ProcessHandle;

        S2E_WINMON2_ALLOCATE_VM AllocateVirtualMemory;
        S2E_WINMON2_FREE_VM FreeVirtualMemory;
        S2E_WINMON2_PROTECT_VM ProtectVirtualMemory;
        S2E_WINMON2_MAP_SECTION MapViewOfSection;
        S2E_WINMON2_UNMAP_SECTION UnmapViewOfSection;

        S2E_WINMON2_NORMALIZED_NAME NormalizedName;
    };
} S2E_WINMON2_COMMAND;

class WindowsMonitor : public OSMonitor, public IPluginInvoker {
    S2E_PLUGIN
public:
    typedef std::vector<ModuleDescriptor> ModuleList;
    typedef std::set<std::string> StringSet;

    WindowsMonitor(S2E *s2e) : OSMonitor(s2e) {
    }

    void initialize();

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_ACCESS_FAULT &> onAccessFault;

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_ALLOCATE_VM &> onNtAllocateVirtualMemory;

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_FREE_VM &> onNtFreeVirtualMemory;

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_PROTECT_VM &> onNtProtectVirtualMemory;

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_MAP_SECTION &> onNtMapViewOfSection;

    sigc::signal<void, S2EExecutionState *, const S2E_WINMON2_UNMAP_SECTION &> onNtUnmapViewOfSection;

    sigc::signal<void, S2EExecutionState *, uint64_t /* syscall id */, uint64_t /* pc */, uint64_t /* stack */
                 >
        onSyscall;

    struct MemoryInformation {
        uint64_t CommitCharge;
        uint64_t VirtualSize;
        uint64_t PeakVirtualSize;
        uint64_t PeakCommitCharge;

        MemoryInformation() {
            CommitCharge = VirtualSize = PeakVirtualSize = PeakCommitCharge = 0;
        }
    };

private:
    TranslationBlockTracer *m_tbTracer;
    MemoryTracer *m_memTracer;
    Vmi *m_vmi;
    bool m_debugDpc;
    bool m_debugAccessFault;

    llvm::StringMap<std::string> m_normalizedNames;

    S2E_WINMON2_KERNEL_STRUCTS m_kernel;
    uint64_t m_kernelStart;
    vmi::windows::DBGKD_GET_VERSION64 m_versionBlock;

    /* Thread and process cache */
    S2EExecutionState *m_cachedState;
    uint64_t m_cachedPid;
    uint64_t m_cachedTid;
    uint64_t m_cachedEthread;
    uint64_t m_cachedEprocess;

    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, enum special_instruction_t type,
                                          const special_instruction_data_t *data);

    void onTranslateSoftInterruptStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                       uint64_t pc, unsigned vector);

    void onSyscallInst(S2EExecutionState *state, uint64_t pc);
    void onSyscallInt(S2EExecutionState *state, uint64_t pc);
    void processSyscall(S2EExecutionState *state, uint64_t pc, uint64_t syscallId, uint64_t stack);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc,
                             bool staticTarget, uint64_t targetPc);

    void onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState);

    void onPageDirectoryChange(S2EExecutionState *state, uint64_t previous, uint64_t current);

    void onPrivilegeChange(S2EExecutionState *state, unsigned previous, unsigned current);

    void onSystemImageLoad(S2EExecutionState *state, uint64_t pc);
    void onDriverLoad(S2EExecutionState *state, uint64_t pc);
    void onDriverUnload(S2EExecutionState *state, uint64_t pc);
    void onPerfLogImageUnload(S2EExecutionState *state, uint64_t pc);
    void onKiRetireDpcCallSite(S2EExecutionState *state, uint64_t pc);
    void enableInstrumentation(S2EExecutionState *state);

    bool checkNewProcess(S2EExecutionState *state, bool fireEvent);

    void opcodeInitKernelStructs(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_WINMON2_COMMAND &command);

    bool getModuleDescriptorFromCommand(S2EExecutionState *state, const S2E_WINMON2_COMMAND &command,
                                        ModuleDescriptor &module);

    template <typename DRIVER_OBJECT, typename MODULE_ENTRY>
    bool readDriverDescriptor(S2EExecutionState *state, uint64_t pDriverDesc, ModuleDescriptor &DriverDesc);
    bool readDriverDescriptorFromParameter(S2EExecutionState *state, ModuleDescriptor &DriverDesc);

    template <typename UNICODE_STRING>
    bool getDriver(S2EExecutionState *state, uint64_t expectedSize, uint64_t expectedEntryPoint,
                   const UNICODE_STRING &nameOrPath, uint64_t baseAddress, ModuleDescriptor &desc);

    template <typename LIST_ENTRY, typename MODULE_ENTRY, typename POINTER>
    bool readModuleListGeneric(S2EExecutionState *state, ModuleList &modules, const StringSet &filter);

    bool readModuleList(S2EExecutionState *state, ModuleList &modules, const StringSet &filter);

    bool getKernelStack(S2EExecutionState *state, uint64_t pEThread, uint64_t *bottom, uint64_t *size);
    bool getDpcStack(S2EExecutionState *state, uint64_t *bottom, uint64_t *size);

    void clearCache();

    std::string GetNormalizedPath(const std::string &path);
    void NormalizePath(const std::string &path, std::string &normalizedPath, std::string &fileName);

    template <typename UNICODE_STRING> void unloadModule(S2EExecutionState *state);

    std::shared_ptr<vmi::PEFile> getFromDiskOrMemory(S2EExecutionState *state, const std::string &modulePath,
                                                     const std::string &moduleName, uint64_t loadBase);

public:
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    // XXX: should be private, but plugins might want to force an update
    // if they suspect the value might be wrong.
    bool initCurrentProcessThreadId(S2EExecutionState *state);

    virtual bool isKernelAddress(uint64_t pc) const {
        assert(m_initialized);
        if (!m_kernelStart) {
            return false;
        }
        return pc >= m_kernelStart;
    }

    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *bottom, uint64_t *size);

    bool CheckPanic(uint64_t eip) const {
        assert(m_initialized);
        eip = eip - m_kernel.KernelLoadBase + m_kernel.KernelNativeBase;
        return m_kernel.KeBugCheckEx && m_kernel.KeBugCheckEx == eip;
    }

    uint64_t getKdDebuggerDataBlock() const {
        assert(m_initialized);
        return m_kernel.KdDebuggerDataBlock - m_kernel.KernelNativeBase + m_kernel.KernelLoadBase;
    }

    uint64_t getKprcbAddress() const {
        assert(m_initialized);
        return m_kernel.KPRCB;
    }

    bool isCheckedBuild() const {
        assert(m_initialized);
        return m_versionBlock.MajorVersion == 0xC;
    }

    const vmi::windows::DBGKD_GET_VERSION64 &getVersionBlock() const {
        assert(m_initialized);
        return m_versionBlock;
    }

    /// Address of the function in the guest kernel that will handle the crash for us.
    /// Useful to perform complex OS-specific stuff (e.g, generating crash dumps).
    uint64_t getCrashRedirectionRoutine() const {
        assert(m_initialized);
        return m_kernel.BugCheckHook;
    }

    const S2E_WINMON2_KERNEL_STRUCTS &getKernelStruct() const {
        assert(m_initialized);
        return m_kernel;
    }

    uint64_t getProcess(S2EExecutionState *state, uint64_t pid) const;
    uint64_t getProcessParent(S2EExecutionState *state, uint64_t pid) const;

    uint64_t getCurrentProcess(S2EExecutionState *state) {
        assert(m_cachedState == state && m_cachedEprocess);
        return m_cachedEprocess;
    }

    inline uint64_t getCurrentThread(S2EExecutionState *state) {
        assert(m_cachedState == state && m_cachedEthread);
        return m_cachedEthread;
    }

    inline uint64_t getCurrentProcessId(S2EExecutionState *state) {
        assert(m_cachedState == state && m_cachedPid != (uint64_t) -1);
        return m_cachedPid;
    }

    inline uint64_t getCurrentThreadId(S2EExecutionState *state) {
        assert(m_cachedState == state && m_cachedTid != (uint64_t) -1);
        return m_cachedTid;
    }

    uint64_t getPid(S2EExecutionState *state) {
        return getCurrentProcessId(state);
    }

    uint64_t getTid(S2EExecutionState *state) {
        return getCurrentThreadId(state);
    }

    uint64_t getKernelStart() const {
        assert(m_initialized);
        return m_kernelStart;
    }

    static uint64_t getTidReg(S2EExecutionState *state);

    uint64_t getPidFromHandle(S2EExecutionState *state, uint64_t ownerPid, uint64_t handle) const;
    bool getMemoryStatisticsForCurrentProcess(S2EExecutionState *state, MemoryInformation &info);

    bool moduleUnloadSupported() const {
        return m_kernel.PerfLogImageUnload != 0;
    }

    bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) {
        return false;
    }

    /* protection: RWX in octal */
    bool getVirtualMemoryInfo(S2EExecutionState *state, uint64_t Process, uint64_t Address, uint64_t *StartAddress,
                              uint64_t *EndAddress, uint64_t *Protection);

    bool dumpVad(S2EExecutionState *state);

    QDict *getTrapInformation(S2EExecutionState *state, uint64_t trapInfo, uint64_t *pc, uint64_t *sp);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_WINDOWSMONITOR2_H
