///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include <ntddk.h>

static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)(LONG_PTR)-1;

NTSTATUS ProcessOpenHandle(_In_ ULONG ProcessID, _Out_ PHANDLE Handle);
NTSTATUS ProcessQueryInfo(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS Class, _Out_ PVOID *Data);
NTSTATUS ProcessGetImageNameFromHandle(_In_ HANDLE ProcessHandle, _Inout_ PUNICODE_STRING ProcessImageName);
NTSTATUS ProcessGetImageNameFromPid(_In_ ULONG ProcessId, _Inout_ PUNICODE_STRING ProcessImageName);
NTSTATUS ProcessGetImageName(_In_ PEPROCESS Process, _Inout_ PUNICODE_STRING ProcessImageName);
