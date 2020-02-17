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

#pragma once
extern "C" {
#include "../utils.h"
#include "../config/config.h"
}

#pragma warning(push)
#pragma warning(disable: 26477) // We can't use nullptr here because of generic types

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
    RET RetVal = 0;
    INT Inject = 0;
    UINT8 InvokeOriginal = 0;
    CHAR *SymbolicVarName = nullptr;

    LOG("Calling %s from %p\n", FunctionName, (PVOID)CallSite);

    if (!g_config.FaultInjectionActive) {
        goto original;
    }

    Inject = FaultInjDecideInjectFault(CallSite, reinterpret_cast<UINT_PTR>(Orig));
    if (!Inject) {
        goto original;
    }

    if (!FaultInjectionCreateVarName(FunctionName, &SymbolicVarName)) {
        LOG("Could not create variable name\n");
        goto original;
    }

    InvokeOriginal = S2ESymbolicChar(SymbolicVarName, 1);

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

#pragma warning(pop)