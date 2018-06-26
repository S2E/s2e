///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fltKernel.h>

extern "C" {
#include <s2e/s2e.h>
#include <s2e/GuestCodeHooking.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

PFILE_LOCK S2EHook_FsRtlAllocateFileLock(
    _In_opt_ PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine,
    _In_opt_ PUNLOCK_ROUTINE UnlockRoutine
)
{
    UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    return FaultInjTemplate1<PFILE_LOCK>(
        CallSite, "FsRtlAllocateFileLock", FALSE, nullptr, &FsRtlAllocateFileLock,
        CompleteLockIrpRoutine, UnlockRoutine
    );
}

NTSTATUS S2EHook_FsRtlProcessFileLock(
    _In_ PFILE_LOCK FileLock,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
)
{
    UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FsRtlProcessFileLock", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FsRtlProcessFileLock,
        FileLock, Irp, Context
    );
}

NTSTATUS S2EHook_FsRtlRegisterFileSystemFilterCallbacks(
    _DRIVER_OBJECT       *FilterDriverObject,
    PFS_FILTER_CALLBACKS Callbacks
)
{
    UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FsRtlRegisterFileSystemFilterCallbacks", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FsRtlRegisterFileSystemFilterCallbacks,
        FilterDriverObject, Callbacks
    );
}

const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelFsHooks[] = {
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "FsRtlAllocateFileLock", S2EHook_FsRtlAllocateFileLock),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "FsRtlProcessFileLock", S2EHook_FsRtlProcessFileLock),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "FsRtlRegisterFileSystemFilterCallbacks", S2EHook_FsRtlRegisterFileSystemFilterCallbacks),
    S2E_KERNEL_FCN_HOOK_END()
};
