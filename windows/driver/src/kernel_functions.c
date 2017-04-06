///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>
#include <s2e/s2e.h>
#include "kernel_functions.h"

PSGETPROCESSPB g_pPsGetProcessPeb;
GET_PROCESS_IMAGE_NAME g_pGetProcessImageFileName;

// MmGetSystemRoutineAddress returns PVOID when it shoudl return FARPROC
#pragma warning(disable:4055)

VOID InitializeKernelFunctionPointers(VOID)
{
    UNICODE_STRING MethodName;

    RtlInitUnicodeString(&MethodName, L"PsGetProcessPeb");
    g_pPsGetProcessPeb = (PSGETPROCESSPB)MmGetSystemRoutineAddress(&MethodName);

    if (!g_pPsGetProcessPeb) {
        S2EKillState(0, "could not find PsGetProcessPeb routine\n");
    }

    RtlInitUnicodeString(&MethodName, L"PsGetProcessImageFileName");
    g_pGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&MethodName);

    if (!g_pGetProcessImageFileName) {
        S2EKillState(0, "could not find PsGetProcessImageFileName routine\n");
    }
}
