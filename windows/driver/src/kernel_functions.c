///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>
#include <s2e/s2e.h>
#include "log.h"
#include "kernel_functions.h"

PSGETPROCESSPB g_pPsGetProcessPeb;
GET_PROCESS_IMAGE_NAME g_pGetProcessImageFileName;

// MmGetSystemRoutineAddress returns PVOID when it shoudl return FARPROC
#pragma warning(disable:4055)

NTSTATUS InitializeKernelFunctionPointers(VOID)
{
    NTSTATUS Status;
    UNICODE_STRING MethodName;

    RtlInitUnicodeString(&MethodName, L"PsGetProcessPeb");
    g_pPsGetProcessPeb = (PSGETPROCESSPB)MmGetSystemRoutineAddress(&MethodName);

    if (!g_pPsGetProcessPeb) {
        LOG("Could not find PsGetProcessPeb routine\n");
        Status = STATUS_NOT_FOUND;
        goto err;
    }

    RtlInitUnicodeString(&MethodName, L"PsGetProcessImageFileName");
    g_pGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&MethodName);

    if (!g_pGetProcessImageFileName) {
        LOG("Could not find PsGetProcessImageFileName routine\n");
        Status = STATUS_NOT_FOUND;
        goto err;
    }

    Status = STATUS_SUCCESS;

err:
    return Status;
}
