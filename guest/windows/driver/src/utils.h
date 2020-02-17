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