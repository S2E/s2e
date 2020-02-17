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

extern "C" {
#include <s2e/s2e.h>
#include <s2e/GuestCodeHooking.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C" {

PVOID S2EHook_ExAllocatePool(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes
)
{
    const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    const BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
    return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePool", RaiseOnFailure, nullptr, &ExAllocatePool, PoolType,
                                    NumberOfBytes);
}

PVOID S2EHook_ExAllocatePoolWithQuota(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes
)
{
    const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    const BOOLEAN RaiseOnFailure = TRUE;
    return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithQuota", RaiseOnFailure, nullptr,
                                    &ExAllocatePoolWithQuota, PoolType, NumberOfBytes);
}

PVOID S2EHook_ExAllocatePoolWithQuotaTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
{
    const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    const BOOLEAN RaiseOnFailure = !(PoolType & POOL_QUOTA_FAIL_INSTEAD_OF_RAISE);
    return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithQuotaTag", RaiseOnFailure, nullptr,
                                    &ExAllocatePoolWithQuotaTag, PoolType, NumberOfBytes, Tag);
}

PVOID S2EHook_ExAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
{
    const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    const BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
    return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithTag", RaiseOnFailure, nullptr, &ExAllocatePoolWithTag,
                                    PoolType, NumberOfBytes, Tag);
}

PVOID S2EHook_ExAllocatePoolWithTagPriority(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _In_ EX_POOL_PRIORITY Priority
)
{
    const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
    const BOOLEAN RaiseOnFailure = PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE;
    return FaultInjTemplate1<PVOID>(CallSite, "ExAllocatePoolWithTagPriority", RaiseOnFailure, nullptr,
                                    &ExAllocatePoolWithTagPriority, PoolType, NumberOfBytes, Tag, Priority);
}

// Note: the documentation states that this function always returns STATUS_SUCCESS.
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff545317(v=vs.85).aspx
// We still inject faults for future-proofing.
NTSTATUS S2EHook_ExInitializeResourceLite(
    _Out_ PERESOURCE Resource
)
{
    if (g_config.FaultInjectionOverapproximate) {
        const UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        const BOOLEAN RaiseOnFailure = FALSE;
        return FaultInjTemplate1<NTSTATUS>(CallSite, "ExInitializeResourceLite", RaiseOnFailure,
                                           STATUS_INSUFFICIENT_RESOURCES, &ExInitializeResourceLite, Resource);
    } else {
        return ExInitializeResourceLite(Resource);
    }
}

const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelExHooks[] = {
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExAllocatePool", S2EHook_ExAllocatePool),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExAllocatePoolWithQuota", S2EHook_ExAllocatePoolWithQuota),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExAllocatePoolWithQuotaTag", S2EHook_ExAllocatePoolWithQuotaTag),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExAllocatePoolWithTag", S2EHook_ExAllocatePoolWithTag),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExAllocatePoolWithTagPriority", S2EHook_ExAllocatePoolWithTagPriority),
    S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "ExInitializeResourceLite", S2EHook_ExInitializeResourceLite),
    S2E_KERNEL_FCN_HOOK_END()
};

}
