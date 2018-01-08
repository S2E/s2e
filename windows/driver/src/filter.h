#pragma once

#include <ntddk.h>

NTSTATUS FilterRegister(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS FilterUnregister(VOID);
