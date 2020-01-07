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

PVOID S2EHook_MmGetSystemRoutineAddress(
    _In_ PUNICODE_STRING SystemRoutineName
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<PVOID>(CallSite, "MmGetSystemRoutineAddress", FALSE, nullptr, &MmGetSystemRoutineAddress,
                                    SystemRoutineName);
}

const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelMmHooks[] = {
    // Failing MmGetSystemRoutineAddress may cause false positives in WPP tracing code
    // S2E_KERNEL_FCN_HOOK("ntoskrnl.exe", "MmGetSystemRoutineAddress", S2EHook_MmGetSystemRoutineAddress),
    S2E_KERNEL_FCN_HOOK_END()
};

}
