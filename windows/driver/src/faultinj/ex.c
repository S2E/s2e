///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>

#include <s2e/s2e.h>
#include <s2e/GuestCodePatching.h>

#include "../log.h"

#include "faultinj.h"
#include "apis.h"

PVOID S2EHook_ExAllocatePoolWithTag(
    /* IN */ POOL_TYPE PoolType,
    /* IN */ SIZE_T NumberOfBytes,
    /* IN */ ULONG Tag
)
{
    PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();

    LOG("Calling %s from %p\n", __FUNCTION__, (PVOID)CallSite);

    if (!FaultInjectionCreateVarName("ntoskrnl.exe", "ExAllocatePoolWithTag", CallSite, SymbolicVarName, sizeof(SymbolicVarName))) {
        LOG("Could not create variable name\n");
        goto original;
    }

    Inject = FaultInjDecideInjectFault(CallSite, (UINT_PTR)&ExAllocatePoolWithTag);
    if (!Inject) {
        goto original;
    }

    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {
        LOG("Invoking original function %s\n", __FUNCTION__);
        goto original;
    }

    if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
    }

    return NULL;

original:

    RetVal = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    S2EMessageFmt("%s returned %#x\n", "ExAllocatePoolWithTag", RetVal);
    return RetVal;
}

const S2E_HOOK g_kernelExHooks[] = {
    { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePoolWithTag", (UINT_PTR)S2EHook_ExAllocatePoolWithTag },
    { 0,0,0 }
};
