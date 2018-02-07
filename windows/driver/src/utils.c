///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fltKernel.h>

#include "adt/strings.h"
#include <s2e/ModuleMap.h>

#include "log.h"
#include "utils.h"

#define STACK_FRAME_COUNT 32

VOID S2EDumpBackTrace(VOID)
{
    PVOID BackTrace[STACK_FRAME_COUNT] = { 0 };

    USHORT CapturedCount = RtlCaptureStackBackTrace(0, STACK_FRAME_COUNT, BackTrace, NULL);

    LOG("Backtrace (items: %d)\n", CapturedCount);
    for (USHORT i = 0; i < CapturedCount; ++i) {
        S2E_MODULE_INFO Info;

        UINT_PTR Ptr = (UINT_PTR)BackTrace[i];
        RtlZeroMemory(&Info, sizeof(Info));

        if (S2EModuleMapGetModuleInfo(Ptr, 0, &Info)) {
            UINT_PTR RelativeAddress = Ptr - (UINT_PTR)Info.RuntimeLoadBase + (UINT_PTR)Info.NativeLoadBase;
            LOG("%p %s:%p\n", (PVOID) Ptr, Info.ModuleName, (PVOID) RelativeAddress);
        } else {
            LOG("%p\n", (PVOID)Ptr);
        }
    }
}

_Success_(return)
NTSTATUS S2EEncodeBackTraceForKnownModules(
    _Out_ PCHAR *Buffer,
    _Out_opt_ PULONG Hash,
    _In_ ULONG FramesToSkip
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    CHAR StrAddr[32] = { 0 };
    S2E_MODULE_INFO PrevInfo;
    PVOID BackTrace[STACK_FRAME_COUNT] = { 0 };

    RtlZeroMemory(&PrevInfo, sizeof(PrevInfo));

    *Buffer = NULL;

    USHORT CapturedCount = RtlCaptureStackBackTrace(FramesToSkip, STACK_FRAME_COUNT, BackTrace, Hash);
    for (USHORT i = 0; i < CapturedCount; ++i) {
        S2E_MODULE_INFO Info;

        UINT_PTR Ptr = (UINT_PTR)BackTrace[i];
        RtlZeroMemory(&Info, sizeof(Info));

        if (S2EModuleMapGetModuleInfo(Ptr, 0, &Info)) {
            const UINT64 RelativeAddress = Ptr - Info.RuntimeLoadBase + Info.NativeLoadBase;

            if (!strcmp(PrevInfo.ModuleName, Info.ModuleName)) {
                // Omit identical consecutive module names to reduce the size of the string
                RtlStringCbPrintfA(StrAddr, sizeof(StrAddr), "-%llx", RelativeAddress);
            } else {
                RtlStringCbPrintfA(StrAddr, sizeof(StrAddr), " %s:%llx", Info.ModuleName, RelativeAddress);
            }

            Status = StringCatInPlace(Buffer, StrAddr);
            if (!NT_SUCCESS(Status)) {
                LOG("Could not concatenate strings\n");
                goto err;
            }

            PrevInfo = Info;
        } else {
            // Skip anything that couldn't be resolved
        }
    }

    return Status;

err:
    if (*Buffer) {
        ExFreePool(*Buffer);
        *Buffer = NULL;
    }

    return Status;
}
