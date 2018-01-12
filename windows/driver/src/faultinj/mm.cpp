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
    PVOID S2EHook_MmGetSystemRoutineAddress(
        _In_ PUNICODE_STRING SystemRoutineName
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<PVOID>(CallSite, "MmGetSystemRoutineAddress", FALSE, NULL, &MmGetSystemRoutineAddress, SystemRoutineName);
    }

    const S2E_HOOK g_kernelMmHooks[] = {
        // Failing MmGetSystemRoutineAddress may cause false positives in WPP tracing code
        // { (UINT_PTR)"ntoskrnl.exe", (UINT_PTR)"MmGetSystemRoutineAddress", (UINT_PTR)S2EHook_MmGetSystemRoutineAddress },
        { 0,0,0 }
    };
}
