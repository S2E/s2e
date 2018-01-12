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
    NTSTATUS S2EHook_ObReferenceObjectByHandle(
        _In_ HANDLE Handle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_TYPE ObjectType,
        _In_ KPROCESSOR_MODE AccessMode,
        _Out_ PVOID *Object,
        _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "ObReferenceObjectByHandle", FALSE, STATUS_INSUFFICIENT_RESOURCES, &ObReferenceObjectByHandle,
            Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation
        );
    }

    const S2E_HOOK g_kernelObHooks[] = {
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ObReferenceObjectByHandle", (UINT_PTR)S2EHook_ObReferenceObjectByHandle },
        { 0,0,0 }
    };
}
