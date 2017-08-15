///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>
#include <ntimage.h>
#include <Aux_klib.h>
#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>

#include "kernel_structs.h"
#include "winmonitor.h"
#include "crash.h"
#include "log.h"

/************************************************/

/* These structure is shared with WindowsMonitor */
S2E_WINMON2_KERNEL_STRUCTS g_WinmonKernelStructs;

/**
 * This is for internal use by the driver.
 * It is not used by WindowsMonitor.
 */
KERNEL_STRUCTS g_kernelStructs;

VOID MonitorInitCommon(S2E_WINMON2_COMMAND *Command)
{
    ULONG Major, Minor, Build;
    memset(Command, 0, sizeof(*Command));

    Command->Command = INIT_KERNEL_STRUCTS;
    Command->Structs.PointerSizeInBytes = sizeof(PVOID);
    Command->Structs.KeBugCheckEx = (UINT_PTR)&KeBugCheckEx;
    Command->Structs.BugCheckHook = GetS2ECrashHookAddress();
    Command->Structs.LoadDriverHook = (UINT_PTR)NULL;

    PsGetVersion(&Major, &Minor, &Build, NULL);
    Command->Structs.KernelMajorVersion = Major;
    Command->Structs.KernelMinorVersion = Minor;
    Command->Structs.KernelBuildNumber = Build;
}

static void S2ERegisterModule(const AUX_MODULE_EXTENDED_INFO *Info, UCHAR *BaseName)
{
    S2E_WINMON2_COMMAND Command;

    LOG("Module Name:%s (%s) LoadBase:%#p Size:%#x\n",
        Info->FullPathName,
        BaseName,
        Info->BasicInfo.ImageBase,
        Info->ImageSize
    );

    Command.Command = LOAD_DRIVER;
    Command.Module.FileNameOffset = Info->FileNameOffset;

    RtlStringCchCopyA((char *)Command.Module.FullPathName,
                      sizeof(Command.Module.FullPathName) - 1,
                      (const char*)Info->FullPathName);

    Command.Module.LoadBase = (UINT_PTR)Info->BasicInfo.ImageBase;
    Command.Module.Size = Info->ImageSize;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

static VOID CheckAccess(PVOID Buffer, SIZE_T Size)
{
    //
    // XXX: this is unsafe. The system could deallocate
    // the memory between the probe and the use.
    // Should lock it in memory instead.
    //

    UINT_PTR Base = ((UINT_PTR)Buffer) & ~0xFFF;
    UINT_PTR Limit = ((UINT_PTR)Buffer) + Size;
    if (Limit & 0xFFF) {
        Limit += 0x1000;
        Limit &= ~0xFFF;
    }

    while (Base < Limit) {
        if (!MmIsAddressValid((PVOID)Base)) {
            ExRaiseAccessViolation();
        }
        Base += 0x1000;
    }
}

static NTSTATUS RegisterKernelStructures(PVOID KernelBase)
{
    INT i;
    IMAGE_NT_HEADERS *NtHeaders;
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)KernelBase;
    CheckAccess(DosHeader, sizeof(*DosHeader));

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG("Incorrect image DOS signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (IMAGE_NT_HEADERS*)((UINT_PTR)KernelBase + DosHeader->e_lfanew);
    CheckAccess(NtHeaders, sizeof(*NtHeaders));

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LOG("Incorrect image NT signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    LOG("Kernel image checksum: %#x\n", NtHeaders->OptionalHeader.CheckSum);

    for (i = 0; g_KernelStructHandlers[i].CheckSum != 0; ++i) {
        if (NtHeaders->OptionalHeader.CheckSum == g_KernelStructHandlers[i].CheckSum) {
            g_KernelStructHandlers[i].Handler((UINT_PTR)KernelBase, NtHeaders->OptionalHeader.ImageBase);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS FindKernelAndRegisterStructures(_In_ AUX_MODULE_EXTENDED_INFO *Info, _In_ ULONG Count)
{
    ULONG i;
    NTSTATUS Status = STATUS_NOT_FOUND;

    for (i = 0; i < Count; ++i) {
        UCHAR *BaseName = &Info[i].FullPathName[Info[i].FileNameOffset];
        STRING ModuleName;
        STRING KernelName;
        RtlInitString(&ModuleName, (PCSZ)BaseName);
        RtlInitString(&KernelName, "ntoskrnl");
        BaseName = (UCHAR*)_strlwr((char*)BaseName);
        if (strstr((const char*)BaseName, "ntoskrnl") || strstr((const char*)BaseName, "ntkrnlpa")) {
            try {
                Status = RegisterKernelStructures(Info[i].BasicInfo.ImageBase);
                if (NT_SUCCESS(Status)) {
                    break;
                }
            } except (EXCEPTION_EXECUTE_HANDLER) {
                LOG("Exception while parsing %s\n", BaseName);
            }
        }
    }

    return Status;
}

static VOID RegisterKernelDrivers(_In_ AUX_MODULE_EXTENDED_INFO *Info, _In_ ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; ++i) {
        UCHAR *BaseName = &Info[i].FullPathName[Info[i].FileNameOffset];
        S2ERegisterModule(&Info[i], BaseName);
    }
}

NTSTATUS RegisterLoadedModules()
{
    AUX_MODULE_EXTENDED_INFO *Info = NULL;
    ULONG Count;
    ULONG BufferSize = 0;

    NTSTATUS Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        goto err;
    }

    //Get the size for the buffer
    Status = AuxKlibQueryModuleInformation(&BufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(Status)) {
        goto err;
    }

    Info = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(NonPagedPool, BufferSize, 0x12345);
    if (!Info) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Status = AuxKlibQueryModuleInformation(&BufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), Info);
    if (!NT_SUCCESS(Status)) {
        goto err;
    }

    Count = BufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);

    Status = FindKernelAndRegisterStructures(Info, Count);
    if (!NT_SUCCESS(Status)) {
        S2EKillState(0, "Could not load kernel data info. Make sure that s2e.sys supports the guest kernel.");
        goto err;
    }

    RegisterKernelDrivers(Info, Count);

err:
    if (Info) {
        ExFreePool(Info);
    }

    return Status;
}

//Driver load invocation is at
//0000000140492769 call    qword ptr [rbx+58h]
//Preceded by event KMPnPEvt_DriverInit_Start
//call EtwWrite

//Scan the memory to find the kernel's load base
//==> would be useful to hook specific functions from the S2E plugins

VOID InitializeWindowsMonitor(VOID)
{
    LOG("InitializeWindowsMonitor\n");
    //GS contains the pointer to KPCR structure
    //KdDebugger block pointer seems to be NULL.
    //void *GsBase = (void*)__readmsr(IA32_GS_BASE);
    //LOG("GsBase=%p\n", GsBase);
    RegisterLoadedModules();

    //AuxKlibQueryModuleInformation
    //can be used to retrieve the list of loaded modules

    //Check if BugCheckDumpIoCallback works.

    //Could use OB_OPERATION_REGISTRATION to track
    //process/thread creation deletion.
    //Sample code: http://code.msdn.microsoft.com/windowshardware/ObCallback-Sample-67a47841

    //PsSetLoadImageNotifyRoutine
}
