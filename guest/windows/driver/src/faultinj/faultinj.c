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

#include <fltKernel.h>
#include <s2e/ModuleMap.h>
#include <s2e/KeyValueStore.h>

#include "../adt/strings.h"
#include "../log.h"
#include "apis.h"
#include "faultinj.h"
#include "../utils.h"
#include "../config/config.h"

BOOLEAN *g_faultInjOverApproximate;

_Success_(return)
BOOLEAN FaultInjectionCreateVarName(
    _In_ LPCSTR FunctionName,
    _Out_ PCHAR *VarName
)
{
    BOOLEAN Result = FALSE;
    NTSTATUS Status;
    CHAR Prefix[128];
    CHAR *BackTraceStr = NULL;

    Status = S2EEncodeBackTraceForKnownModules(&BackTraceStr, NULL, 3);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not encode backtrace\n");
        goto err;
    }

    RtlStringCbPrintfA(Prefix, sizeof(Prefix), "FaultInjInvokeOrig %s ", FunctionName);

    *VarName = StringCat(Prefix, BackTraceStr);
    if (!*VarName) {
        LOG("Could not concatenate string\n");
        goto err;
    }

    Result = TRUE;

err:
    if (BackTraceStr) {
        ExFreePool(BackTraceStr);
    }

    return Result;
}

#define STACK_FRAME_COUNT 32
#define CALL_SITE_ID_SIZE 128

// Compute a hash of the call stack and store it in a global key-value store.
// This ensures that different states don't inject the same faults needlessly.
// TODO: it may not be required to pass callsite if we use the stack trace
BOOLEAN FaultInjDecideInjectFault(
    _In_ UINT_PTR CallSite,
    _In_ UINT_PTR TargetFunction
)
{
    S2E_MODULE_INFO Info;
    UINT_PTR ModuleAddress = CallSite;
    PVOID BackTrace[STACK_FRAME_COUNT] = { 0 };
    CHAR CallSiteId[CALL_SITE_ID_SIZE];
    ULONG Hash;
    UINT64 AlreadyExercised = 0;

    UNREFERENCED_PARAMETER(CallSite);
    UNREFERENCED_PARAMETER(TargetFunction);

    if (S2EModuleMapGetModuleInfo(CallSite, 0, &Info)) {
        ModuleAddress = CallSite - (UINT_PTR)Info.RuntimeLoadBase + (UINT_PTR)Info.NativeLoadBase;
    }

    RtlCaptureStackBackTrace(0, STACK_FRAME_COUNT, BackTrace, &Hash);
    RtlStringCbPrintfA(CallSiteId, sizeof(CallSiteId), "%s_%p_%x", Info.ModuleName, (PVOID)ModuleAddress, Hash);
    LOG("CallSiteId: %s\n", CallSiteId);

    if (!S2EKVSGetValue(CallSiteId, &AlreadyExercised)) {
        // Key not found, means that we have no exercised yet
        if (!S2EKVSSetValue(CallSiteId, 1, NULL)) {
            LOG("Could not set key %s\n", CallSiteId);
        }
    }

    LOG("AlreadyExercised: %d\n", AlreadyExercised);

    return !AlreadyExercised;
}

VOID FaultInjectionInit(VOID)
{
    LOG("Hooking ExXxx apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelExHooks);

    LOG("Hooking MmXxx apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelMmHooks);

    LOG("Hooking PsXxx apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelPsHooks);

    LOG("Hooking ObXxx apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelObHooks);

    LOG("Hooking Registry apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelRegHooks);

    LOG("Hooking FS filter apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelFltHooks);

    LOG("Hooking Fs apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelFsHooks);

    LOG("Hooking Io apis...");
    GuestCodeHookingRegisterLibFcnCallHooks(g_kernelIoHooks);
}
