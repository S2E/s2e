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
#include <s2e/s2e.h>
#include "kernel_structs.h"
#include "crash.h"
#include "log.h"
#include "utils.h"

#include <s2e/WindowsMonitor.h>
#include <s2e/BlueScreenInterceptor.h>

// MmGetSystemRoutineAddress returns PVOID when it shoudl return FARPROC
#pragma warning(disable:4152)

static BOOLEAN BugCheckCallbackRegistered = FALSE;
static KBUGCHECK_REASON_CALLBACK_RECORD BugCheckRecord;

#define CRASH_DUMP_HEADER_SIZE 0x2000
static UINT8 s_BugCheckHeaderBuffer[CRASH_DUMP_HEADER_SIZE];

extern S2E_WINMON2_KERNEL_STRUCTS g_WinmonKernelStructs;

UINT_PTR ToRuntimeAddress(UINT64 Address)
{
    return (UINT_PTR)(Address - (UINT_PTR)g_WinmonKernelStructs.KernelNativeBase
        + (UINT_PTR)g_WinmonKernelStructs.KernelLoadBase);
}

/**
 * Windows 8 x64 encrypts the KdDebuggerDataBlock structure.
 * The variable KdpDataBlockEncoded indicates whether it is
 * encrypted or not. This routine calls the internal Windows
 * functions in order to decrypt the block before generating
 * the crash dump.
 */
VOID DecryptKdDataBlock()
{
    KdCopyDataBlock *Routine;
    PCHAR IsEncoded;

    if (!g_kernelStructs.KdCopyDataBlock) {
        LOG("KdCopyDataBlock is NULL\n");
        return;
    }

    IsEncoded = (PCHAR)(UINT_PTR)ToRuntimeAddress(g_kernelStructs.KdpDataBlockEncoded);

    if (*IsEncoded) {
        Routine = (KdCopyDataBlock*)ToRuntimeAddress(g_kernelStructs.KdCopyDataBlock);
        Routine((PVOID)ToRuntimeAddress(g_WinmonKernelStructs.KdDebuggerDataBlock));
        *IsEncoded = 0;
    }
}

/**
 * Dynamically loads the real KeInitializeCrashDumpHeader routine.
 * Allows the driver to work on WinXP.
 */
static NTSTATUS LfiKeInitializeCrashDumpHeader(
    ULONG DumpType,
    ULONG Flags,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BufferNeeded
)
{
    UNICODE_STRING Str;
    typedef NTSTATUS (*KeInitializeCrashDumpHeader_t)(ULONG DumpType, ULONG Flags, PVOID Buffer,
        ULONG BufferSize, PULONG BufferNeeded);

    static KeInitializeCrashDumpHeader_t _KeInitializeCrashDumpHeader = NULL;

    RtlInitUnicodeString(&Str, L"KeInitializeCrashDumpHeader");
    _KeInitializeCrashDumpHeader = MmGetSystemRoutineAddress(&Str);
    if (!_KeInitializeCrashDumpHeader) {
        return STATUS_NOT_SUPPORTED;
    }

    return _KeInitializeCrashDumpHeader(DumpType, Flags, Buffer, BufferSize, BufferNeeded);
}

/**
 *  WindowsMonitor hooks the KeBugCheckEx function
 *  and redirects execution to here.
 *  This function initializes the bug check header and transmits it to S2E.
 */
NTSTATUS InitializeCrashDumpHeader(ULONG *BufferSize)
{
    NTSTATUS Status;
    ULONG BufferNeeded = 0;

    /* Determine the size for the buffer */
    Status = LfiKeInitializeCrashDumpHeader(
        1 /* DUMP_TYPE_FULL */, 0,
        s_BugCheckHeaderBuffer, 0, &BufferNeeded);

    if (BufferNeeded > 0) {
        LOG("S2EBSODHook: crash dump header of size %#x\n", BufferNeeded);

        if (BufferNeeded > CRASH_DUMP_HEADER_SIZE) {
            LOG("S2EBSODHook: required buffer too big");
            Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            Status = LfiKeInitializeCrashDumpHeader(
                1 /* DUMP_TYPE_FULL */, 0,
                s_BugCheckHeaderBuffer, BufferNeeded, NULL);

            if (!NT_SUCCESS(Status)) {
                LOG("S2EBSODHook: failed to initialize crash dump header\n");
            }
        }
    }

    *BufferSize = BufferNeeded;
    return Status;
}

NTSTATUS InitializeManualCrash(PVOID *Header, UINT64 *HeaderSize)
{
    ULONG BufferNeeded = 0;
    if (!Header || !HeaderSize) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeCrashDumpHeader(&BufferNeeded);

    if (IsWindows8OrAbove(&g_kernelStructs.Version)) {
        DecryptKdDataBlock();
    }

    KeSaveStateForHibernate(g_kernelStructs.PRCBProcessorStateOffset);

    *Header = s_BugCheckHeaderBuffer;
    *HeaderSize = BufferNeeded;
    return STATUS_SUCCESS;
}

VOID S2EBSODHook(
    ULONG BugCheckCode,
    ULONG_PTR BugCheckParameter1,
    ULONG_PTR BugCheckParameter2,
    ULONG_PTR BugCheckParameter3,
    ULONG_PTR BugCheckParameter4
)
{
    S2E_BSOD_CRASH Command;
    ULONG BufferNeeded = 0;
    LOG("Invoked S2EBSODHook\n");

    S2EDumpBackTrace();

    InitializeCrashDumpHeader(&BufferNeeded);

    if (IsWindows8OrAbove(&g_kernelStructs.Version)) {
        DecryptKdDataBlock();
    }

    Command.Header = (UINT_PTR)s_BugCheckHeaderBuffer;
    Command.HeaderSize = BufferNeeded;
    Command.Code = BugCheckCode;
    Command.Parameters[0] = BugCheckParameter1;
    Command.Parameters[1] = BugCheckParameter2;
    Command.Parameters[2] = BugCheckParameter3;
    Command.Parameters[3] = BugCheckParameter4;

    S2EInvokePlugin("BlueScreenInterceptor", &Command, sizeof(Command));
    S2EKillState(0, "unreachable code in S2EBSODHook");
}

UINT_PTR GetS2ECrashHookAddress()
{
    if (g_kernelStructs.Version.dwMajorVersion == 0x5 && g_kernelStructs.Version.dwMinorVersion == 0x1) {
        LOG("No S2EBSODHook for this Windows version\n");
        return 0;
    }

    LOG("S2EBSODHook is at %p\n", S2EBSODHook);
    return (UINT_PTR)S2EBSODHook;
}

/*
Info about registering dump devices:
http://www.osronline.com/showThread.cfm?link=82275

typedef struct _DUMP_IRP{
    ULONG unknown1[3];
    PVOID Buffer; //0ch,
    PVOID Buffer1; //10h
    ULONG Length; //14h,
}DUMP_IRP, *PDUMP_IRP;

MMDUMP_FUNCTIONS_DESCRIPTOR

http://www.nosuchcon.org/talks/D3_01_Aaron_Crashdmpster_Diving_Win8.pdf

Hook crashdmp.sys to intercept write calls?
    Seems like the simplest thing to do.
Install a crash control dump filter?

Crash dump filter drivers

Some info about writing dumps
http://media.blackhat.com/bh-us-10/whitepapers/Suiche/BlackHat-USA-2010-Suiche-Blue-Screen-of-the-Death-is-dead-wp.pdf

http://computer.forensikblog.de/en/2008/02/64bit-crash-dumps.html

Interesting data structures
https://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/kd.h?r=2686
_KDDEBUGGER_DATA64
http://computer.forensikblog.de/files/010_templates/DMP.bt

=> Seems to be possible to set the size of the crash dump at run time without rebooting

IopInitializeCrashDump
  - Read registry for config
    \Registry\Machine\System\CurrentControlSet\Control\CrashControl
      AutoReboot
      CrashDumpEnabled

  - IopLoadCrashdumpDriver
  - Allocate mem for CrashdmpDumpBlock
  - CrashdmpInitialized = 1
  Dumpfve.sys, Bitlocker Drive Encryption Crashdump Filter.
  diskdump.sys => used to write dumps to disk

http://www.slideshare.net/CrowdStrike/io-you-own-regaining-control-of-your-disk-in-the-presence-of-bootkits#btnNext

=> patch callback table in crash dump driver???
=> still need to make it work with page file disabled.

-> Disable page file

*/
