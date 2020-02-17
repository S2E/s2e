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