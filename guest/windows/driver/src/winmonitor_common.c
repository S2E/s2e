///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
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

#include <ntddk.h>
#include <ntimage.h>
#include <Aux_klib.h>
#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>

#include "kernel_structs.h"
#include "adt/strings.h"
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
    RTL_OSVERSIONINFOW Version = { 0 };

    memset(Command, 0, sizeof(*Command));

    Command->Command = INIT_KERNEL_STRUCTS;
    Command->Structs.PointerSizeInBytes = sizeof(PVOID);
    Command->Structs.KeBugCheckEx = (UINT_PTR)&KeBugCheckEx;
    Command->Structs.BugCheckHook = GetS2ECrashHookAddress();
    Command->Structs.LoadDriverHook = (UINT_PTR)NULL;

    Version.dwOSVersionInfoSize = sizeof(Version);

    if (!NT_SUCCESS(RtlGetVersion(&Version))) {
        S2EKillState(0, "Could not get version info");
        return;
    }

    Command->Structs.KernelMajorVersion = Version.dwMajorVersion;
    Command->Structs.KernelMinorVersion = Version.dwMinorVersion;
    Command->Structs.KernelBuildNumber = Version.dwBuildNumber;
}


static NTSTATUS S2ERegisterKernelDriver(const AUX_MODULE_EXTENDED_INFO *Info, UCHAR *BaseName)
{
    NTSTATUS Status;
    UNICODE_STRING DriverPath = { 0, 0, NULL };

    LOG("Registering kernel driver: %s (%s) LoadBase:%#p Size:%#x\n",
        Info->FullPathName,
        BaseName,
        Info->BasicInfo.ImageBase,
        Info->ImageSize
    );

    Status = StringToUnicode((LPCSTR)Info->FullPathName, sizeof(Info->FullPathName), &DriverPath);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not allocate unicode string\n");
        goto err;
    }

    WinMon2LoadDriver(&DriverPath, (UINT_PTR)Info->BasicInfo.ImageBase, Info->ImageSize);

    Status = STATUS_SUCCESS;

err:
    StringFree(&DriverPath);
    return Status;
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

    LOG("This version of s2e.sys does not support kernel with checksum %#x. "
        "Check the readme for instructions on how to add support for new kernels.\n",
        NtHeaders->OptionalHeader.CheckSum)
    ;

    return STATUS_NOT_FOUND;
}

static NTSTATUS FindKernelAndRegisterStructures(_In_ AUX_MODULE_EXTENDED_INFO *Info, _In_ ULONG Count)
{
    ULONG i;
    NTSTATUS Status = STATUS_NOT_FOUND;

    LOG("Looking for kernel module in %u modules...\n", Count);

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

static BOOLEAN RegisterKernelDrivers(_In_ AUX_MODULE_EXTENDED_INFO *Info, _In_ ULONG Count)
{
    ULONG i;
    BOOLEAN Success = TRUE;

    for (i = 0; i < Count; ++i) {
        UCHAR *BaseName = &Info[i].FullPathName[Info[i].FileNameOffset];
        NTSTATUS Status = S2ERegisterKernelDriver(&Info[i], BaseName);
        if (!NT_SUCCESS(Status)) {
            LOG("Could not register kernel driver (%#x)\n", Status);
            Success = FALSE;
        }
    }

    return Success;
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
        LOG("Could not query kernel module information (%#x)\n", Status);
        goto err;
    }

    Info = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(NonPagedPoolNx, BufferSize, 0x12345);
    if (!Info) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Status = AuxKlibQueryModuleInformation(&BufferSize, sizeof(AUX_MODULE_EXTENDED_INFO), Info);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not query kernel module information (%#x)\n", Status);
        goto err;
    }

    Count = BufferSize / sizeof(AUX_MODULE_EXTENDED_INFO);

    Status = FindKernelAndRegisterStructures(Info, Count);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not load kernel data info. Make sure that s2e.sys supports the guest kernel (%#x).\n", Status);
        goto err;
    }

    if (!RegisterKernelDrivers(Info, Count)) {
        LOG("There was at least on module that failed to load\n");
        Status = STATUS_UNSUCCESSFUL;
        goto err;
    }

err:
    if (Info) {
        ExFreePool(Info);
    }

    return Status;
}

NTSTATUS InitializeWindowsMonitor(VOID)
{
    NTSTATUS Status;
    LOG("Initializing WindowsMonitor...\n");

    Status = RegisterLoadedModules();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not register loaded modules (%#x)\n", Status);
        goto err;
    }

err:
    return Status;
}
