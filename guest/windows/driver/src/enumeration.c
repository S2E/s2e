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
#include "adt/strings.h"
#include "kernel_structs.h"
#include "kernel_functions.h"
#include "utils/process.h"
#include "log.h"

VOID EnumerateThreads(PEPROCESS Process)
{
    PLIST_ENTRY Head = (PLIST_ENTRY)((UINT_PTR)(Process) + (UINT_PTR)g_kernelStructs.EProcessThreadListHeadOffset);
    PLIST_ENTRY CurrentThreadLink = Head->Flink;
    while (CurrentThreadLink != Head) {
        UINT_PTR pEThread = (UINT_PTR)(CurrentThreadLink) - (UINT_PTR)g_kernelStructs.EThreadThreadListEntry;
        LOG("   ETHREAD %#p ID=%#x\n", pEThread, PsGetThreadId((PETHREAD)pEThread));
        CurrentThreadLink = CurrentThreadLink->Flink;
    }
}

//XXX: Not safe, must not be interrupted
//Need to lock the list and reference process/thread object while processing them.
VOID EnumerateProcesses(VOID)
{
    PLIST_ENTRY Head = g_kernelStructs.PsActiveProcessHead;
    PLIST_ENTRY CurrentProcessLink = Head->Flink;

    while (CurrentProcessLink != Head) {
        UNICODE_STRING ProcessImageName = { 0 };
        NTSTATUS Status;

        UINT_PTR EProcess = (UINT_PTR)(CurrentProcessLink) - (UINT_PTR)g_kernelStructs.EProcessActiveProcessLinkOffset;

        Status = ProcessGetImageName((PEPROCESS)EProcess, &ProcessImageName);
        if (!Status) {
            LOG("Could not get image name for process\n");
            goto err;
        }

        LOG("EPROCESS %#p ID=%#x %wZ\n", EProcess, PsGetProcessId((PEPROCESS)EProcess), &ProcessImageName);
        EnumerateThreads((PEPROCESS)EProcess);

    err:
        StringFree(&ProcessImageName);

        CurrentProcessLink = CurrentProcessLink->Flink;
    }
}
