///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>

extern "C"
{
#include <s2e/s2e.h>
#include <s2e/GuestCodePatching.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C"
{
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "PsCreateSystemThread", FALSE, STATUS_INSUFFICIENT_RESOURCES, &PsCreateSystemThread,
            ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext
        );
    }

    const S2E_HOOK g_kernelPsHooks[] = {
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"PsCreateSystemThread", (UINT_PTR)S2EHook_PsCreateSystemThread },
        { 0,0,0 }
    };
}
