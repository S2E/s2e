///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct _S2E_CONFIG
    {
        // Fault injection instruments kernel API calls and injects errors.
        // This is useful to test driver behavior when API calls fail.
        // For example, you can check that error recovery code works properly
        // if there is not enough memory in the system and that memory allocation
        // starts failing.
        BOOLEAN FaultInjectionEnabled;

        // This flag allows enabling/disabling fault injection at runtime.
        // Note that this is different from FaultInjectionEnabled, whose
        // job is to prepare S2E itself for fault injection.
        // FaultInjectionActive requires FaultInjectionEnabled to be true.
        BOOLEAN FaultInjectionActive;

        // Use this option if you would like to check that your driver
        // can handle arbitrary faults, even if these faults cannot occur
        // on the given operating system. This option helps future-proofing
        // your driver against API documentation bugs and future API upgrades.
        // It may, however, cause false positives.
        BOOLEAN FaultInjectionOverapproximate;
    } S2E_CONFIG;

    extern S2E_CONFIG g_config;

    NTSTATUS ConfigInit(_Out_ S2E_CONFIG *Config);
    VOID ConfigDump(_In_ const S2E_CONFIG *Config);
    NTSTATUS ConfigSet(_Inout_ S2E_CONFIG *Config, _In_ LPCSTR Name, _In_ UINT64 Value);

#ifdef __cplusplus
}
#endif