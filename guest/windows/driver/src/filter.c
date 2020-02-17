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

#include <fltKernel.h>
#include "filter.h"

#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>

#include "log.h"

// TODO: centralize global driver data
typedef struct _NORMALIZER_DATA
{
    PFLT_FILTER Filter;
} NORMALIZER_DATA, *PNORMALIZER_DATA;

NORMALIZER_DATA NormalizerData = { 0 };

static NTSTATUS NormalizerInstanceSetup(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

static NTSTATUS NormalizerQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

static FLT_POSTOP_CALLBACK_STATUS
NormalizerPostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
);

static NTSTATUS UnregisterFilesystemFilter(__in FLT_FILTER_UNLOAD_FLAGS Flags);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, FilterRegister)
#pragma alloc_text(PAGE, NormalizerInstanceSetup)
#pragma alloc_text(PAGE, NormalizerPostCreate)
#endif

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, NormalizerPostCreate },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0, //  Flags
    ContextRegistration, //  Context Registration.
    Callbacks, //  Operation callbacks
    UnregisterFilesystemFilter, //  FilterUnload
    NormalizerInstanceSetup, //  InstanceSetup
    NormalizerQueryTeardown, //  InstanceQueryTeardown
    NULL, //  InstanceTeardownStart
    NULL, //  InstanceTeardownComplete
    NULL, //  GenerateFileName
    NULL, //  GenerateDestinationFileName
    NULL //  NormalizeNameComponent
};

NTSTATUS FilterRegister(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    LOG("registering filesystem filter");

    /* Register with filter manager. */
    Status = FltRegisterFilter(DriverObject, &FilterRegistration, &NormalizerData.Filter);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not register filter (%#x)\n", Status);
        goto err0;
    }

    /* Start filtering I/O. */
    Status = FltStartFiltering(NormalizerData.Filter);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not start filtering (%#x)\n", Status);
        goto err1;
    }

    return Status;

err1: FltUnregisterFilter(NormalizerData.Filter);
err0: return Status;
}

NTSTATUS FilterUnregister(VOID)
{
    return UnregisterFilesystemFilter(0);
}

static NTSTATUS UnregisterFilesystemFilter(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (NormalizerData.Filter) {
        /* Unregister the filter */
        FltUnregisterFilter(NormalizerData.Filter);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NormalizerInstanceSetup(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    ASSERT(FltObjects->Filter == NormalizerData.Filter);

    /* Don't attach to network volumes. */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NormalizerQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

static FLT_POSTOP_CALLBACK_STATUS
NormalizerPostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
)
{
    PFLT_FILE_NAME_INFORMATION OpenFileName = NULL, NormalizedFileName = NULL;
    NTSTATUS Status;
    BOOLEAN HasTilda = FALSE;
    unsigned i;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &OpenFileName);
    if (Status != STATUS_SUCCESS) {
        goto end;
    }

    for (i = 0; i < OpenFileName->Name.Length / sizeof(WCHAR); ++i) {
        if (OpenFileName->Name.Buffer[i] == '~') {
            HasTilda = TRUE;
            break;
        }
    }

    if (!HasTilda) {
        goto end;
    }

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &NormalizedFileName);
    if (Status == STATUS_SUCCESS) {
        /* Some long names may have tildas as well */
        if (!RtlEqualUnicodeString(&OpenFileName->Name, &NormalizedFileName->Name, FALSE)) {
            WinMon2SendNormalizedName(&OpenFileName->Name, &NormalizedFileName->Name);
        }
        //LOG("%s Original:   %S", __FUNCTION__, OpenFileName->Name.Buffer);
        //LOG("%s Normalized: %S", __FUNCTION__, NormalizedFileName->Name.Buffer);
    }

end:

    if (OpenFileName) {
        FltReleaseFileNameInformation(OpenFileName);
    }

    if (NormalizedFileName) {
        FltReleaseFileNameInformation(NormalizedFileName);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
