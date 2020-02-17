///
/// Copyright (C) 2018, Cyberhaven
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
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
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
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
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
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
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
