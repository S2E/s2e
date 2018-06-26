///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once
extern "C" {
#include "../utils.h"
#include "../config/config.h"
}

template <typename RET, typename FCN, typename ... ARGS>
RET FaultInjTemplate1(
    _In_ UINT_PTR CallSite,
    _In_ LPCSTR FunctionName,
    _In_ BOOLEAN RaiseOnFailure,
    _In_opt_ RET DefaultConcreteFailure,
    _In_ FCN Orig,
    ARGS ... Args
)
{
    RET RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR *SymbolicVarName;

    LOG("Calling %s from %p\n", FunctionName, (PVOID)CallSite);

    if (!g_config.FaultInjectionActive) {
        goto original;
    }

    Inject = FaultInjDecideInjectFault(CallSite, (UINT_PTR)Orig);
    if (!Inject) {
        goto original;
    }

    if (!FaultInjectionCreateVarName(FunctionName, &SymbolicVarName)) {
        LOG("Could not create variable name\n");
        goto original;
    }

    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);

    if (SymbolicVarName) {
        ExFreePool(SymbolicVarName);
    }

    if (InvokeOriginal) {
        LOG("Invoking original function %s\n", FunctionName);
        goto original;
    }

    S2EDumpBackTrace();

    if (RaiseOnFailure) {
        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
    }

    return DefaultConcreteFailure;

original:
    RetVal = Orig(Args...);
    S2EMessageFmt("%s returned %#x\n", FunctionName, RetVal);
    return RetVal;
}
