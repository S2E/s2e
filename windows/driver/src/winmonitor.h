///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
