///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_KERNEL_FUNCTIONS_
#define _S2E_KERNEL_FUNCTIONS_

#include <ntddk.h>

typedef PPEB(*PSGETPROCESSPB)(PEPROCESS Process);
typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);

extern PSGETPROCESSPB g_pPsGetProcessPeb;
extern GET_PROCESS_IMAGE_NAME g_pGetProcessImageFileName;

VOID InitializeKernelFunctionPointers(VOID);

#endif
