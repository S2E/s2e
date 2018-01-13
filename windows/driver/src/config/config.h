///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include <ntddk.h>

typedef struct _S2E_CONFIG
{
    // Fault injection instruments kernel API calls and injects errors.
    // This is useful to test driver behavior when API calls fail.
    // For example, you can check that error recovery code works properly
    // if there is not enough memory in the system and that memory allocation
    // starts failing.
    BOOLEAN FaultInjectionEnabled;

    // Use this option if you would like to check that your driver
    // can handle arbitrary faults, even if these faults cannot occur
    // on the given operating system. This option helps future-proofing
    // your driver against API documentation bugs and future API upgrades.
    // It may, however, cause false positives.
    BOOLEAN FaultInjectionOverapproximate;
} S2E_CONFIG;

NTSTATUS ConfigInit(_Out_ S2E_CONFIG *Config);
VOID ConfigDump(_In_ const S2E_CONFIG *Config);
