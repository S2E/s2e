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
#include <s2e/s2e.h>
#include "log.h"
#include "kernel_functions.h"


PsSetContextThread_t PsSetContextThread;
PsGetContextThread_t PsGetContextThread;
ZwQueryInformationProcess_t ZwQueryInformationProcess;
ZwQueryInformationThread_t ZwQueryInformationThread;

static PVOID InitializeApi(LPCWSTR Name)
{
    UNICODE_STRING ApiName;
    RtlInitUnicodeString(&ApiName, Name);
    return MmGetSystemRoutineAddress(&ApiName);
}

typedef struct _API
{
    PCWSTR Name;
    PVOID *Var;
} API;

#define DECLARE_API(Name) {L#Name, (PVOID*) &Name}

#pragma warning(push)
// A data pointer is cast (possibly incorrectly) to a function pointer.
#pragma warning(disable:4055)
static API s_apis[] = {
    DECLARE_API(PsSetContextThread),
    DECLARE_API(PsGetContextThread),
    DECLARE_API(ZwQueryInformationProcess),
    DECLARE_API(ZwQueryInformationThread)
};
#pragma warning(pop)

BOOLEAN ApiInitialize()
{
    for (unsigned i = 0; i < ARRAYSIZE(s_apis); ++i) {
        UNICODE_STRING ApiName;
        RtlInitUnicodeString(&ApiName, s_apis[i].Name);
        *s_apis[i].Var = MmGetSystemRoutineAddress(&ApiName);
        if (!*s_apis[i].Var) {
            LOG("Could not find address of %S\n", s_apis[i].Name);
            return FALSE;
        }
    }

    return TRUE;
}
