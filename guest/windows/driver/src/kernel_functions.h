///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_KERNEL_FUNCTIONS_
#define _S2E_KERNEL_FUNCTIONS_

#include <ntddk.h>

typedef NTSTATUS (NTAPI *PsSetContextThread_t)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode);
typedef NTSTATUS (NTAPI *PsGetContextThread_t)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode);

// Taken from https://www.osronline.com/article.cfm?article=472
typedef NTSTATUS (NTAPI *ZwQueryInformationProcess_t)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_bytecap_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *ZwQueryInformationThread_t)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

extern PsSetContextThread_t PsSetContextThread;
extern PsGetContextThread_t PsGetContextThread;
extern ZwQueryInformationProcess_t ZwQueryInformationProcess;
extern ZwQueryInformationThread_t ZwQueryInformationThread;

BOOLEAN ApiInitialize();


#endif
