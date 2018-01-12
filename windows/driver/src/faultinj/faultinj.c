///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>

#include <s2e/ModuleMap.h>

#include "../log.h"
#include "apis.h"

BOOLEAN FaultInjectionCreateVarName(
    _In_ PCHAR ModuleName,
    _In_ PCHAR FunctionName,
    _In_ UINT_PTR CallSite,
    _Out_ PCHAR VarName,
    _In_ SIZE_T VarNameSize
)
{
    S2E_MODULE_INFO Info;

    if (!S2EModuleMapGetModuleInfo(CallSite, 0, &Info)) {
        LOG("Could not read module info for callsite %p\n", (PVOID)CallSite);
        return FALSE;
    }

    UINT64 RelativeCallSite = CallSite - Info.RuntimeLoadBase + Info.NativeLoadBase;

    sprintf_s(VarName, VarNameSize, "FaultInjInvokeOrig %s:%llx %s:%s",
              Info.ModuleName, RelativeCallSite, ModuleName, FunctionName);

    return TRUE;
}

BOOLEAN FaultInjDecideInjectFault(
    _In_ UINT_PTR CallSite,
    _In_ UINT_PTR TargetFunction
)
{
    UNREFERENCED_PARAMETER(CallSite);
    UNREFERENCED_PARAMETER(TargetFunction);
    return TRUE;
}

VOID FaultInjectionInit(VOID)
{
    LOG("Hooking ExXxx apis...");
    RegisterHooks(g_kernelExHooks);

    LOG("Hooking MmXxx apis...");
    RegisterHooks(g_kernelMmHooks);

    LOG("Hooking PsXxx apis...");
    RegisterHooks(g_kernelPsHooks);

    LOG("Hooking ObXxx apis...");
    RegisterHooks(g_kernelObHooks);

    LOG("Hooking Registry apis...");
    RegisterHooks(g_kernelRegHooks);
}
