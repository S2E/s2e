///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include "../config/config.h"

VOID FaultInjectionInit(VOID);

_Success_(return)
BOOLEAN FaultInjectionCreateVarName(
    _In_ LPCSTR FunctionName,
    _Out_ PCHAR *VarName
);

BOOLEAN FaultInjDecideInjectFault(
    _In_ UINT_PTR CallSite,
    _In_ UINT_PTR TargetFunction
);
