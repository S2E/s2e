///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
