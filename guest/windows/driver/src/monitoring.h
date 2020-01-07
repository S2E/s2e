///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_MONITORING_H_

#define _S2E_MONITORING_H_

#include <ntddk.h>

NTSTATUS MonitoringInitialize(VOID);

VOID MonitoringDeinitialize(VOID);

VOID MonitorWatchPidTermination(DWORD Pid);

#endif
