#pragma once

#include <ntddk.h>

DRIVER_INITIALIZE FilterRegister;

NTSTATUS FilterUnregister(VOID);
