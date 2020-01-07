/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2013 Dependable Systems Lab, EPFL
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

#ifndef S2E_WINDOWS_CRASHDUMP_MONITOR_H

#define S2E_WINDOWS_CRASHDUMP_MONITOR_H

/********************************************************/
/* Communicating with the WindowsCrashMonitor plugin    */

typedef struct _S2E_WINDOWS_USERMODE_CRASH
{
    UINT64 ProgramName;
    UINT64 Pid;
    UINT64 ExceptionCode;
    UINT64 ExceptionAddress;
    UINT64 ExceptionFlags;
} S2E_WINDOWS_USERMODE_CRASH;

typedef enum _S2E_WINDOWS_CRASH_COMMANDS
{
    WINDOWS_USERMODE_CRASH
} S2E_WINDOWS_CRASH_COMMANDS;

typedef struct _S2E_CRASHDUMP_OPAQUE
{
    UINT64 Buffer;
    UINT64 Size;
} S2E_CRASHDUMP_OPAQUE;

// Allow nameless structs
#pragma warning(disable:4201)

typedef struct _S2E_WINDOWS_CRASH_COMMAND
{
    S2E_WINDOWS_CRASH_COMMANDS Command;
    union
    {
        S2E_WINDOWS_USERMODE_CRASH UserModeCrash;
    };
    /* Optional, used by the crash dump plugin. */
    S2E_CRASHDUMP_OPAQUE Dump;
} S2E_WINDOWS_CRASH_COMMAND;

#endif
