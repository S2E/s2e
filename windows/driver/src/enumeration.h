///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_ENUMERATION_H_

#define _S2E_ENUMERATION_H_

#include <ntddk.h>

VOID EnumerateThreads(PEPROCESS Process);
VOID EnumerateProcesses(VOID);

#endif
