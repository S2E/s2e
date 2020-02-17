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

#define USER_APP

#pragma warning(disable:4706)
#pragma warning(disable:4201)

#include <stdio.h>
#include <windows.h>

#include <s2e/s2e.h>
#include <s2e/WindowsCrashMonitor.h>
#include "drvctl.h"

BOOL GetProcessName(DWORD Pid, LPSTR Name, DWORD MaxLen)
{
    HANDLE hProcess = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        FALSE, Pid);
    if (!hProcess) {
        printf("drvctl: OpenProcess failed\n");
        return FALSE;
    }

    if (!GetModuleBaseNameA(hProcess, NULL, Name, MaxLen)) {
        char *Error = GetErrorString(GetLastError());
        printf("drvctl: GetModuleFileName failed %#s\n", Error);
        LocalFree(Error);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hProcess);
    return TRUE;
}

#if defined(_AMD64_)
static BOOL IsWow64(DWORD Pid, PBOOL Result)
{
    BOOL Ret;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);

    if (!hProcess) {
        S2EMessageFmt("drvctl: Could not open process pid %d\n", Pid);
        return FALSE;
    }

    Ret = IsWow64Process(hProcess, Result);

    CloseHandle(hProcess);
    return Ret;
}
#endif

static VOID PrintThreadContext(DWORD Pid, DWORD Tid)
{
    HANDLE hThread;
    CONTEXT Context;
#if defined(_AMD64_)
    BOOL Wow = FALSE;
#endif

    S2EMessageFmt("drvctl: Printing thread context (tid: %u)\n", Tid);

    /* Retrieve thread context information */
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, Tid);
    if (hThread == NULL) {
        S2EMessageFmt("drvctl: Could not open thread tid %d\n", Tid);
        goto e0;
    }

#if defined(_AMD64_)
    if (!IsWow64(Pid, &Wow)) {
        S2EMessageFmt("drvctl: Could not decide if thread %d is syswow64 process\n", Tid);
        goto e1;
    }
#else
    UNREFERENCED_PARAMETER(Pid);
#endif

    Context.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(hThread, &Context)) {
        S2EMessageFmt("drvctl: Could not get context of thread %d\n", Tid);
        goto e1;
    }

#if defined(_AMD64_)
    S2EMessageFmt("drvctl: RIP:%#llx RSP:%#llx RBP:%#llx \n", Context.Rip, Context.Rsp, Context.Rbp);
    S2EMessageFmt("drvctl: RAX:%#llx RCX:%#llx RDX:%#llx RBX:%#llx\n", Context.Rax, Context.Rcx, Context.Rdx, Context.Rbx);
    S2EMessageFmt("drvctl: RSI:%#llx RDI:%#llx\n", Context.Rdi, Context.Rdi);
#else
    S2EMessageFmt("drvctl: Eip: %#x\n", Context.Eip);
#endif

e1: CloseHandle(hThread);
e0: return;
}

VOID PrintExceptionRecord(DWORD Pid, DWORD Tid, const EXCEPTION_RECORD *Record)
{
    DWORD i;
    CHAR ProgramName[MAX_PATH + 1] = { 0 };
    if (!GetProcessName(Pid, ProgramName, sizeof(ProgramName) - 1)) {
        S2EMessageFmt("drvctl: GetProcessName failed\n");
    }

    S2EMessageFmt("drvctl: Exception record for %s - pid: %u\n", ProgramName, Pid);
    S2EMessageFmt("drvctl: Code: %#x Flags: %#x Address: %p NumParams: %u\n",
                  Record->ExceptionCode, Record->ExceptionFlags, Record->ExceptionAddress,
                  Record->NumberParameters);

    for (i = 0; i < Record->NumberParameters; ++i) {
        S2EMessageFmt("drvctl: param[%d]: %#llx\n", i, (UINT64)Record->ExceptionInformation[i]);
    }

    PrintThreadContext(Pid, Tid);
}

int ReportBug(DWORD Pid, const EXCEPTION_RECORD *Record)
{
    S2E_WINDOWS_CRASH_COMMAND Command;
    CHAR ProgramName[MAX_PATH + 1] = { 0 };

    Command.Command = WINDOWS_USERMODE_CRASH;
    Command.UserModeCrash.Pid = Pid;
    Command.UserModeCrash.ExceptionAddress = (UINT64)Record->ExceptionAddress;
    Command.UserModeCrash.ExceptionCode = Record->ExceptionCode;
    Command.UserModeCrash.ExceptionFlags = Record->ExceptionFlags;
    Command.UserModeCrash.ProgramName = 0;

    if (GetProcessName(Pid, ProgramName, sizeof(ProgramName) - 1)) {
        Command.UserModeCrash.ProgramName = (UINT64)ProgramName;
    } else {
        printf("drvctl: GetProcessName failed\n");
    }

    printf("drvctl: Program name: %s\n", ProgramName);

    if (!S2EGetVersionSafe()) {
        printf("drvctl: Not running in S2E mode\n");
        return -1;
    }

    return S2EInvokeWindowsCrashMonitor(&Command);
}

VOID DebugApp(DWORD Pid, DWORD EventId)
{
    BOOL Attached = FALSE;
    DEBUG_EVENT DebugEvent;
    EXCEPTION_RECORD LastExceptionRecord;
    DWORD ContinueFlag = DBG_CONTINUE;
    BOOL Ret = DebugActiveProcess(Pid);
    if (!Ret) {
        printf("drvctl: Could not debug process %d\n", Pid);
        return;
    }

    while ((Ret = WaitForDebugEvent(&DebugEvent, 1000))) {
        printf("drvctl: Event code %x\n", DebugEvent.dwDebugEventCode);

        switch (DebugEvent.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            S2EMessageFmt("CREATE_PROCESS_DEBUG_EVENT filename: %s\n", DebugEvent.u.CreateProcessInfo.lpImageName);
        } break;

        case EXIT_PROCESS_DEBUG_EVENT: {
            S2EMessageFmt("EXIT_PROCESS_DEBUG_EVENT\n");
            ReportBug(Pid, &LastExceptionRecord);
        } break;

        case EXCEPTION_DEBUG_EVENT: {
            DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
            S2EMessageFmt("EXCEPTION_DEBUG_EVENT pid: %x tid: %x\n"
                   "code: %#x "
                   "address: %#x "
                   "flags: %#x "
                   "first chance: %d\n",
                   DebugEvent.dwProcessId,
                   DebugEvent.dwThreadId,
                   ExceptionCode,
                   DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
                   DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags,
                   DebugEvent.u.Exception.dwFirstChance);

            PrintExceptionRecord(Pid, DebugEvent.dwThreadId, &DebugEvent.u.Exception.ExceptionRecord);

            if (!Attached && (ExceptionCode == EXCEPTION_BREAKPOINT)) {
                //printf("Attached!\n");
                SetEvent(ULongToHandle(EventId));
                CloseHandle(ULongToHandle(EventId));
                Attached = TRUE;
            }

            LastExceptionRecord = DebugEvent.u.Exception.ExceptionRecord;

            if (!DebugEvent.u.Exception.dwFirstChance) {
                ReportBug(Pid, &DebugEvent.u.Exception.ExceptionRecord);
            } else {
                ContinueFlag = DBG_EXCEPTION_NOT_HANDLED;
            }
        } break;

        default: {
            S2EMessageFmt("drvctl: Unhandled event code %d\n", DebugEvent.dwDebugEventCode);
        }
        }

        if (!ContinueDebugEvent(DebugEvent.dwProcessId,
            DebugEvent.dwThreadId, ContinueFlag)) {
            printf("drvctl: Failed ContinueDebugEvent\n");
        }
    }

    //DebugActiveProcessStop(Pid);
    EventId;
}
