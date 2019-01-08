///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>

extern "C" {
#include <s2e/s2e.h>
#include <s2e/GuestCodeHooking.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C" {

NTSTATUS S2EHook_PsCreateSystemThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "PsCreateSystemThread", FALSE, STATUS_INSUFFICIENT_RESOURCES, &PsCreateSystemThread,
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext
    );
}

const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelPsHooks[] = {
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "PsCreateSystemThread", S2EHook_PsCreateSystemThread),
    S2E_KERNEL_FCN_HOOK_END()
};

}
