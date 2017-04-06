///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fltKernel.h>

#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>

#include "log.h"

typedef struct _NORMALIZER_DATA
{
    PFLT_FILTER Filter;
} NORMALIZER_DATA, *PNORMALIZER_DATA;

NORMALIZER_DATA NormalizerData = { 0 };

NTSTATUS RegisterFilesystemFilter(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS NormalizerInstanceSetup(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS NormalizerQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
NormalizerPostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS UnregisterFilesystemFilter(__in FLT_FILTER_UNLOAD_FLAGS Flags);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, RegisterFilesystemFilter)
#pragma alloc_text(PAGE, NormalizerInstanceSetup)
#pragma alloc_text(PAGE, NormalizerPostCreate)
#endif

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, NormalizerPostCreate},
    { IRP_MJ_OPERATION_END}
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    UnregisterFilesystemFilter,         //  FilterUnload
    NormalizerInstanceSetup,               //  InstanceSetup
    NormalizerQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

NTSTATUS RegisterFilesystemFilter(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    LOG("registering filesystem filter");

    /* Register with filter manager. */
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &NormalizerData.Filter);

    if (!NT_SUCCESS(status)) {
        goto err0;
    }

    /* Start filtering I/O. */
    status = FltStartFiltering(NormalizerData.Filter);
    if (!NT_SUCCESS(status)) {
        goto err1;
    }

    return status;

err1: FltUnregisterFilter(NormalizerData.Filter);
err0: return status;
}

NTSTATUS UnregisterFilesystemFilter(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (NormalizerData.Filter) {
        /* Unregister the filter */
        FltUnregisterFilter(NormalizerData.Filter);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NormalizerInstanceSetup(
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

NTSTATUS NormalizerQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS
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

NTSTATUS MyRtlDuplicateUnicodeString(PUNICODE_STRING Dest, PUNICODE_STRING Source)
{
    *Dest = *Source;
    Dest->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Source->MaximumLength, 0xdead);
    if (!Dest->Buffer) {
        return STATUS_NO_MEMORY;
    }

    memcpy(Dest->Buffer, Source->Buffer, Source->MaximumLength);

    return STATUS_SUCCESS;
}

VOID MyRtlFreeUnicodeString(PUNICODE_STRING Str)
{
    ExFreePoolWithTag(Str->Buffer, 0xdead);
}
