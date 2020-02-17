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
#include <Aux_klib.h>

#ifndef S2E_CRASH_H

#define S2E_CRASH_H

#if _WIN32_WINNT >= _WIN32_WINNT_WS03

NTKERNELAPI
NTSTATUS
KeInitializeCrashDumpHeader(
    _In_ ULONG DumpType,
    _In_ ULONG Flags,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG BufferNeeded
);

#endif

typedef NTSTATUS NTAPI KdCopyDataBlock(PVOID Buffer);

VOID DecryptKdDataBlock();
UINT_PTR GetS2ECrashHookAddress();
NTSTATUS InitializeCrashDumpHeader(ULONG *BufferSize);
NTSTATUS InitializeManualCrash(PVOID *Header, UINT64 *HeaderSize);

/* PKPROCESSOR_STATE State */
VOID __cdecl KeSaveStateForHibernate(PVOID State);

#endif
