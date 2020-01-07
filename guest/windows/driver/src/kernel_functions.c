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
