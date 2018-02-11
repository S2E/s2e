/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2013 Dependable Systems Lab, EPFL
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

#ifndef WINDOWSMONITOR2_H

#define WINDOWSMONITOR2_H

#include "s2e.h"

/********************************************************/
/* WindowsMonitor stuff */
#define R_FS 4
#define R_GS 5

typedef enum S2E_WINMON2_COMMANDS
{
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

typedef struct S2E_WINMON2_KERNEL_STRUCTS
{
    UINT64 KernelNativeBase;
    UINT64 KernelLoadBase;
    UINT64 KernelChecksum;
    UINT64 KernelMajorVersion;
    UINT64 KernelMinorVersion;
    UINT64 KernelBuildNumber;

    UINT64 LoadDriverPc;
    UINT64 UnloadDriverPc;
    UINT64 LoadDriverHook;

    UINT64 PointerSizeInBytes;

    UINT64 KeBugCheckEx;
    UINT64 BugCheckHook;

    UINT64 KPCR;

    // The KPRCB is a struct at the end of the KPCR
    UINT64 KPRCB;

    UINT64 KdDebuggerDataBlock; // Address in the kernel file
    UINT64 KdVersionBlock; // Stored in the KPCR

    /**
     * Index of the segment that contains the pointer
     * to the current thread.
     */
    UINT64 EThreadSegment; // R_FS / RG_S
    UINT64 EThreadSegmentOffset;
    UINT64 EThreadStackBaseOffset;
    UINT64 EThreadStackLimitOffset;
    UINT64 EThreadProcessOffset;
    UINT64 EThreadCidOffset;

    UINT64 EProcessUniqueIdOffset;
    UINT64 EProcessCommitChargeOffset;
    UINT64 EProcessVirtualSizeOffset;
    UINT64 EProcessPeakVirtualSizeOffset;
    UINT64 EProcessCommitChargePeakOffset;
    UINT64 EProcessVadRootOffset;
    UINT64 EProcessExitStatusOffset;

    UINT64 DPCStackBasePtr;
    UINT64 DPCStackSize;

    UINT64 PsLoadedModuleList;

    UINT64 PerfLogImageUnload;

    UINT64 KiRetireDpcCallSite;
} S2E_WINMON2_KERNEL_STRUCTS;

#define S2E_MODULE_MAX_LEN 255

typedef struct S2E_WINMON2_MODULE
{
    UINT64 LoadBase;
    UINT64 Size;
    UINT64 FileNameOffset;
    UCHAR FullPathName[S2E_MODULE_MAX_LEN + 1];
} S2E_WINMON2_MODULE;

typedef struct S2E_WINMON2_MODULE2
{
    UINT64 LoadBase;
    UINT64 Size;
    UINT64 Pid;
    UINT64 UnicodeModulePath;
    UINT64 UnicodeModulePathSizeInBytes;
} S2E_WINMON2_MODULE2;

typedef struct S2E_WINMON2_ACCESS_FAULT
{
    UINT64 Address;
    UINT64 AccessMode;
    UINT64 StatusCode;
    UINT64 TrapInformation;
    UINT64 ReturnAddress;
} S2E_WINMON2_ACCESS_FAULT;

typedef struct S2E_WINMON2_PROCESS_CREATION
{
    UINT64 ProcessId;
    UINT64 ParentProcessId;
    UINT64 EProcess;
    UINT64 UnicodeImagePath;
    UINT64 UnicodeImagePathSizeInBytes;
} S2E_WINMON2_PROCESS_CREATION;

typedef struct S2E_WINMON2_THREAD_CREATION
{
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 EThread;
} S2E_WINMON2_THREAD_CREATION;

typedef struct S2E_WINMON2_PROCESS_HANDLE_CREATION
{
    /* The process that requested the handle */
    UINT64 SourceProcessId;

    /* The process that the handle is referencing */
    UINT64 TargetProcessId;

    /* The handle itself */
    UINT64 Handle;
} S2E_WINMON2_PROCESS_HANDLE_CREATION;

typedef struct S2E_WINMON2_ALLOCATE_VM
{
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 AllocationType;
    UINT64 Protection;
} S2E_WINMON2_ALLOCATE_VM;

typedef struct S2E_WINMON2_FREE_VM
{
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 FreeType;
} S2E_WINMON2_FREE_VM;

typedef struct S2E_WINMON2_PROTECT_VM
{
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 NewProtection;
    UINT64 OldProtection;
} S2E_WINMON2_PROTECT_VM;

typedef struct S2E_WINMON2_MAP_SECTION
{
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 AllocationType;
    UINT64 Win32Protect;
} S2E_WINMON2_MAP_SECTION;

typedef struct S2E_WINMON2_UNMAP_SECTION
{
    UINT64 Status;
    UINT64 EProcess;
    UINT64 Pid;
    UINT64 BaseAddress;
} S2E_WINMON2_UNMAP_SECTION;

typedef struct S2E_WINMON2_NORMALIZED_NAME
{
    UINT64 OriginalName;
    UINT64 OriginalNameSizeInBytes;
    UINT64 NormalizedName;
    UINT64 NormalizedNameSizeInBytes;
} S2E_WINMON2_NORMALIZED_NAME;

// Allow nameless structs
#pragma warning(push)
#pragma warning(disable:4201)
typedef struct S2E_WINMON2_COMMAND
{
    S2E_WINMON2_COMMANDS Command;

    union
    {
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
#pragma warning(pop)

static VOID WinMon2SendNormalizedName(PUNICODE_STRING Original, PUNICODE_STRING Normalized)
{
    S2E_WINMON2_COMMAND Command;
    Command.Command = STORE_NORMALIZED_NAME;
    Command.NormalizedName.OriginalName = (UINT_PTR)Original->Buffer;
    Command.NormalizedName.OriginalNameSizeInBytes = (UINT_PTR)Original->Length;
    Command.NormalizedName.NormalizedName = (UINT_PTR)Normalized->Buffer;
    Command.NormalizedName.NormalizedNameSizeInBytes = (UINT_PTR)Normalized->Length;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

static VOID WinMon2LoadImage(PCUNICODE_STRING FilePath, UINT64 LoadBase, UINT64 Size, UINT64 Pid)
{
    S2E_WINMON2_COMMAND Command;

    Command.Command = LOAD_IMAGE;
    Command.Module2.LoadBase = (UINT_PTR)LoadBase;
    Command.Module2.Size = Size;
    Command.Module2.Pid = Pid;
    Command.Module2.UnicodeModulePath = (UINT_PTR)FilePath->Buffer;
    Command.Module2.UnicodeModulePathSizeInBytes = FilePath->Length;
    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

static VOID WinMon2LoadDriver(PCUNICODE_STRING FilePath, UINT64 LoadBase, UINT64 Size)
{
    S2E_WINMON2_COMMAND Command;

    Command.Command = LOAD_DRIVER;
    Command.Module2.LoadBase = (UINT_PTR)LoadBase;
    Command.Module2.Size = Size;
    Command.Module2.Pid = 0;
    Command.Module2.UnicodeModulePath = (UINT_PTR)FilePath->Buffer;
    Command.Module2.UnicodeModulePathSizeInBytes = FilePath->Length;
    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

static VOID WinMon2LoadUnloadProcess(
    _In_ BOOLEAN IsLoad,
    _In_ PCUNICODE_STRING ProcessImageName,
    _In_ UINT64 ProcessId,
    _In_ UINT64 ParentId,
    _In_ UINT64 EProcess
)
{
    S2E_WINMON2_COMMAND Command = { 0 };

    Command.Process.EProcess = EProcess;
    Command.Process.ProcessId = ProcessId;
    Command.Process.ParentProcessId = ParentId;
    Command.Process.UnicodeImagePath = (UINT_PTR)ProcessImageName->Buffer;
    Command.Process.UnicodeImagePathSizeInBytes = (UINT_PTR)ProcessImageName->Length;
    Command.Command = IsLoad ? LOAD_PROCESS : UNLOAD_PROCESS;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif
