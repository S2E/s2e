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
    PVOID S2EHook_ExAllocatePool(
        _In_ POOL_TYPE PoolType,
        _In_ SIZE_T NumberOfBytes
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
        return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePool", RaiseOnFailure, nullptr, &ExAllocatePool, PoolType, NumberOfBytes);
    }

    PVOID S2EHook_ExAllocatePoolWithQuota(
        _In_ POOL_TYPE PoolType,
        _In_ SIZE_T NumberOfBytes
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        BOOLEAN RaiseOnFailure = TRUE;
        return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithQuota", RaiseOnFailure, nullptr, &ExAllocatePoolWithQuota, PoolType, NumberOfBytes);
    }

    PVOID S2EHook_ExAllocatePoolWithQuotaTag(
        _In_ POOL_TYPE PoolType,
        _In_ SIZE_T NumberOfBytes,
        _In_ ULONG Tag
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        BOOLEAN RaiseOnFailure = !(PoolType & POOL_QUOTA_FAIL_INSTEAD_OF_RAISE);
        return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithQuotaTag", RaiseOnFailure, nullptr, &ExAllocatePoolWithQuotaTag, PoolType, NumberOfBytes, Tag);
    }

    PVOID S2EHook_ExAllocatePoolWithTag(
        _In_ POOL_TYPE PoolType,
        _In_ SIZE_T NumberOfBytes,
        _In_ ULONG Tag
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
        return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithTag", RaiseOnFailure, nullptr, &ExAllocatePoolWithTag, PoolType, NumberOfBytes, Tag);
    }

    PVOID S2EHook_ExAllocatePoolWithTagPriority(
        _In_ POOL_TYPE PoolType,
        _In_ SIZE_T NumberOfBytes,
        _In_ ULONG Tag,
        _In_ EX_POOL_PRIORITY Priority
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
        return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithTagPriority", RaiseOnFailure, nullptr, &ExAllocatePoolWithTagPriority, PoolType, NumberOfBytes, Tag, Priority);
    }

    // Note: the documentation states that this function always returns STATUS_SUCCESS.
    // https://msdn.microsoft.com/en-us/library/windows/hardware/ff545317(v=vs.85).aspx
    // We still inject faults for future-proofing.
    NTSTATUS S2EHook_ExInitializeResourceLite(
        _Out_ PERESOURCE Resource
    )
    {
        if (g_config.FaultInjectionOverapproximate) {
            UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
            BOOLEAN RaiseOnFailure = FALSE;
            return FaultInjTemplate1<NTSTATUS>(CallSite, "ExInitializeResourceLite", RaiseOnFailure, STATUS_INSUFFICIENT_RESOURCES, &ExInitializeResourceLite, Resource);
        } else {
            return ExInitializeResourceLite(Resource);
        }
    }


    const S2E_HOOK g_kernelExHooks[] = {
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePool", (UINT_PTR)S2EHook_ExAllocatePool },
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePoolWithQuota", (UINT_PTR)S2EHook_ExAllocatePoolWithQuota },
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePoolWithQuotaTag", (UINT_PTR)S2EHook_ExAllocatePoolWithQuotaTag },
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePoolWithTag", (UINT_PTR)S2EHook_ExAllocatePoolWithTag },
        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExAllocatePoolWithTagPriority", (UINT_PTR)S2EHook_ExAllocatePoolWithTagPriority },

        { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"ExInitializeResourceLite", (UINT_PTR)S2EHook_ExInitializeResourceLite },
        { 0,0,0 }
    };
}
