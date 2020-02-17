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
