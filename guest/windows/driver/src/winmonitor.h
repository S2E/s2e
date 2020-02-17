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

#ifndef _S2E_WINMONITOR_H_

#define _S2E_WINMONITOR_H_

#include <s2e/WindowsMonitor.h>

typedef VOID REGISTER_KERNEL_STRUCTS(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase);

typedef struct REGISTER_KERNEL_STRUCTS_HANDLERS
{
    UINT32 CheckSum;
    REGISTER_KERNEL_STRUCTS *Handler;
} REGISTER_KERNEL_STRUCTS_HANDLERS;

VOID MonitorInitCommon(S2E_WINMON2_COMMAND *Command);

extern S2E_WINMON2_KERNEL_STRUCTS g_WinmonKernelStructs;
extern REGISTER_KERNEL_STRUCTS_HANDLERS g_KernelStructHandlers[];

NTSTATUS InitializeWindowsMonitor(VOID);

#define IA32_FS_BASE 0xc0000100
#define IA32_GS_BASE 0xc0000101

#endif
