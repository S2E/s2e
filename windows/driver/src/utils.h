///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

VOID S2EDumpBackTrace(VOID);

_Success_(return)
NTSTATUS S2EEncodeBackTraceForKnownModules(
    _Out_ PCHAR *Buffer,
    _Out_opt_ PULONG Hash,
    _In_ ULONG FramesToSkip
);


static inline BOOLEAN IsWindows8OrAbove(_In_ const RTL_OSVERSIONINFOEXW *Version)
{
    if (Version->dwMajorVersion > 6) {
        return TRUE;
    }

    if (Version->dwMajorVersion < 6) {
        return FALSE;
    }

    return Version->dwMinorVersion >= 2;
}

static inline BOOLEAN IsWindows10OrAbove(_In_ const RTL_OSVERSIONINFOEXW *Version)
{
    return Version->dwMajorVersion >= 10;
}