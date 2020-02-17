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

#include <ntddk.h>
#include <Ntstrsafe.h>

#include "../log.h"

#include "config.h"

#define TAG_CFG 'conf'

#define S2E_CONFIG_KEY L"\\Registry\\Machine\\Software\\S2E"
#define S2E_CONFIG_FAULT_INJ_ENABLED L"FaultInjectionEnabled"
#define S2E_CONFIG_FAULT_INJ_OVERAPPROXIMATE L"FaultInjectionOverapproximate"

NTSTATUS ConfigGetDword(HANDLE Key, PUNICODE_STRING Value, DWORD *Data)
{
    NTSTATUS Status;
    KEY_VALUE_FULL_INFORMATION *Info = NULL;
    ULONG ResultLength = 0;

    Status = ZwQueryValueKey(Key, Value, KeyValueFullInformation, NULL, 0, &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL) {
        LOG("Could not read config value %wZ (%#x)\n", Value, Status);
        goto err;
    }

    Info = ExAllocatePoolWithTag(PagedPool, ResultLength, TAG_CFG);
    if (!Info) {
        LOG("Could not allocate memory for registry value\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Status = ZwQueryValueKey(Key, Value, KeyValueFullInformation, Info, ResultLength, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not read config value %wZ (%#x)\n", Value, Status);
        goto err;
    }

    if (Info->Type != REG_DWORD || Info->DataLength != sizeof(DWORD)) {
        LOG("Invalid value type (%#x)\n", Info->Type);
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    *Data = *(DWORD*)(((PCHAR)Info) + Info->DataOffset);

err:
    if (Info) {
        ExFreePoolWithTag(Info, TAG_CFG);
    }

    return Status;
}

NTSTATUS ConfigInit(_Out_ S2E_CONFIG *Config)
{
    UNICODE_STRING S2EConfigKey = RTL_CONSTANT_STRING(S2E_CONFIG_KEY);
    UNICODE_STRING S2EFaultInjEnabled = RTL_CONSTANT_STRING(S2E_CONFIG_FAULT_INJ_ENABLED);

    OBJECT_ATTRIBUTES oa = { 0 };
    ULONG CreateDisposition = 0;
    NTSTATUS Status;
    HANDLE Key = NULL;
    DWORD Data;

    RtlZeroMemory(Config, sizeof(*Config));

    InitializeObjectAttributes(&oa, &S2EConfigKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateKey(&Key, KEY_READ, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &CreateDisposition);
    if (!NT_SUCCESS(Status)) {
        LOG("Failed to open S2E config key %wZ (%#x)\n", &S2EConfigKey, Status);
        goto err;
    }

    Status = ConfigGetDword(Key, &S2EFaultInjEnabled, &Data);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get fault injection configuration %wZ\\%wZ (%#x)\n", &S2EConfigKey, &S2EFaultInjEnabled, Status);
        goto err;
    }
    Config->FaultInjectionEnabled = Data != 0;

err:

    if (Key) {
        ZwClose(Key);
    }

    return Status;
}

NTSTATUS ConfigSet(_Inout_ S2E_CONFIG *Config, _In_ LPCSTR Name, _In_ UINT64 Value)
{
    NTSTATUS Status = STATUS_SUCCESS;

    LOG("Setting %s=%#x\n", Name, Value);

    if (!strcmp(Name, "FaultInjectionEnabled")) {
        LOG("Cannot set FaultInjectionEnabled at runtime\n");
        Status = STATUS_INVALID_PARAMETER;
    } else if (!strcmp(Name, "FaultInjectionActive")) {
        Config->FaultInjectionActive = (BOOLEAN)Value;
    } else if (!strcmp(Name, "FaultInjectionOverapproximate")) {
        Config->FaultInjectionOverapproximate = (BOOLEAN)Value;
    } else {
        LOG("Invalid option %s=%#x\n", Name, Value);
        Status = STATUS_INVALID_PARAMETER;
    }

    if (NT_SUCCESS(Status)) {
        ConfigDump(Config);
    }

    return Status;
}

VOID ConfigDump(_In_ const S2E_CONFIG *Config)
{
    LOG("s2e.sys configuration:\n");
    LOG("  FaultInjectionEnabled:         %d\n", Config->FaultInjectionEnabled);
    LOG("  FaultInjectionActive:          %d\n", Config->FaultInjectionActive);
    LOG("  FaultInjectionOverapproximate: %d\n", Config->FaultInjectionOverapproximate);
}
