///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///
///
#ifndef _TEST_CTL_H_

#define _TEST_CTL_H_

#include <windows.h>

#include <s2ectl.h>

INT S2EGetVersionSafe(VOID);
VOID DebugApp(DWORD Pid, DWORD EventId);
char *GetErrorString(DWORD ErrorCode);

typedef struct _S2E_WINDOWS_CRASH_COMMAND S2E_WINDOWS_CRASH_COMMAND;
INT S2EInvokeWindowsCrashMonitor(S2E_WINDOWS_CRASH_COMMAND *Command);

DWORD WINAPI GetModuleBaseNameA(
  HANDLE hProcess,
  HMODULE hModule,
  LPCSTR lpBaseName,
  DWORD nSize
);

#endif
