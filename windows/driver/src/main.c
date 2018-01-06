///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>
#include <wdmsec.h>

#include <s2e/s2e.h>
#include <s2ectl.h>
#include "crash.h"

#include <s2e/StaticStateMerger.h>
#include <s2e/WindowsCrashMonitor.h>
#include <s2e/GuestCodePatching.h>

#include "kernel_functions.h"
#include "kernel_hooks.h"
#include "kernel_structs.h"
#include "monitoring.h"
#include "winmonitor.h"
#include "filter.h"

#include "log.h"

DRIVER_UNLOAD DriverUnload;

NTSTATUS S2EOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS S2EClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS S2EIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#define NT_DEVICE_NAME          L"\\Device\\S2EDriver"
#define DOS_DEVICE_NAME         L"\\DosDevices\\S2EDriver"

PDEVICE_OBJECT g_DeviceObject = NULL;

static UINT32 GetOSVersion(VOID)
{
    RTL_OSVERSIONINFOEXW Version;

    Version.dwOSVersionInfoSize = sizeof(Version);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&Version);

    UINT32 NTVersion =
        (Version.dwMajorVersion << 24) |
        (Version.dwMinorVersion << 16) |
        (Version.wServicePackMajor << 8);

    LOG("Detected kernel version %d.%d.%d (NTDDI %#x)\n",
        Version.dwMajorVersion,
        Version.dwMinorVersion,
        Version.dwBuildNumber,
        NTVersion);

    return NTVersion;
}

static NTSTATUS ValidateS2E()
{
    NTSTATUS Status;
    INT Version;

    try {
        Version = S2EGetVersion();
    } except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("Could not execute S2E opcode");
        Status = STATUS_NO_SUCH_DEVICE;
        goto err;
    }

    if (Version == 0) {
        LOG("Not running in S2E mode");
        Status = STATUS_UNSUCCESSFUL;
        goto err;
    }

    Status = STATUS_SUCCESS;
err:
    return Status;
}

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING NtDeviceName;
    UNICODE_STRING Win32DeviceName;
    PDEVICE_OBJECT DeviceObject = NULL;

    BOOLEAN S2EValidated = FALSE;
    BOOLEAN MonitoringInited = FALSE;
    BOOLEAN DeviceObjectInited = FALSE;
    BOOLEAN SymlinkInited = FALSE;
    BOOLEAN FsFilterInited = FALSE;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    LOG("Driver build for %#x\n", _WIN32_WINNT);

    g_kernelStructs.Version = GetOSVersion();

    Status = ValidateS2E();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not validate S2E (%#x)\n", Status);
        goto err;
    }
    S2EValidated = TRUE;

    Status = InitializeKernelFunctionPointers();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not initialize kernel function pointers (%#x)\n", Status);
        goto err;
    }

    Status = InitializeWindowsMonitor();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not initialize WindowsMonitor (%#x)\n", Status);
        goto err;
    }

    Status = MonitoringInitialize();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not initialize monitoring (%#x)\n", Status);
        goto err;
    }
    MonitoringInited = TRUE;

    RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
    Status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &NtDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        NULL,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        LOG("Could not init device object (%#x)\n", Status);
        goto err;
    }
    DeviceObjectInited = TRUE;

    RtlInitUnicodeString(&Win32DeviceName, DOS_DEVICE_NAME);
    Status = IoCreateSymbolicLink(&Win32DeviceName, &NtDeviceName);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not create symbolic link (%#x)\n", Status);
        goto err;
    }
    SymlinkInited = TRUE;

    Status = FilterRegister(DriverObject, RegistryPath);
    if (!NT_SUCCESS(Status)) {
        LOG("RegisterFilesystemFilter failed (status=%#x)", Status);
        goto err;
    }
    FsFilterInited = TRUE;

    g_DeviceObject = DeviceObject;

    InitializeKernelHooks();
    S2ERegisterMergeCallback();

#if defined(_AMD64_)
    S2ERegisterReturnHook64();
#endif

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = S2EOpen;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = S2EClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = S2EIoControl;

    return Status;

err:
    if (FsFilterInited) {
        FilterUnregister();
    }

    if (SymlinkInited) {
        IoDeleteSymbolicLink(&Win32DeviceName);
    }

    if (DeviceObjectInited) {
        IoDeleteDevice(DeviceObject);
    }

    if (MonitoringInited) {
        MonitoringDeinitialize();
    }

    if (!NT_SUCCESS(Status)) {
        if (S2EValidated) {
            S2EKillState(0, "An error occurred during s2e.sys initialization. Check debug.txt for more details.");
        }
    }

    return Status;
}

NTSTATUS S2EOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp->FileObject->FsContext = NULL;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

NTSTATUS S2EClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS NtStatus;
    PIO_STACK_LOCATION IrpSp;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    NtStatus = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

static NTSTATUS S2EIoCtlRegisterModule(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PCHAR DriverName = Buffer;
    ULONG NameLength = 0;

    if (!InputBufferLength) {
        LOG("Invaliid input length\n");
        Status = STATUS_INVALID_USER_BUFFER;
        goto err;
    }

    while (DriverName[NameLength] && (NameLength < 128 && (NameLength < InputBufferLength - 1))) {
        NameLength++;
    }

    DriverName[NameLength] = 0;
    LOG("IOCTL_S2E_REGISTER_MODULE (%s)", DriverName);

    RegisterModule(DriverName);

err:
    return Status;
}

static NTSTATUS S2EIoCtlUserModeCrash(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status = STATUS_SUCCESS;
    S2E_WINDOWS_CRASH_COMMAND Command;

    PVOID CrashOpaque;
    UINT64 CrashOpaqueSize;

    if (InputBufferLength < sizeof(Command)) {
        LOG("IOCTL_S2E_WINDOWS_USERMODE_CRASH command too short\n");
        Status = STATUS_INVALID_USER_BUFFER;
        goto err;
    }

    Command = *(S2E_WINDOWS_CRASH_COMMAND *)Buffer;

    //S2E_WINDOWS_USERMODE_CRASH::ProgramName is the offset
    //of the string. Convert to absolute pointer.
    if (Command.UserModeCrash.ProgramName >= InputBufferLength) {
        LOG("IOCTL_S2E_WINDOWS_USERMODE_BUG invalid program name string\n");
        Status = STATUS_INVALID_USER_BUFFER;
        goto err;
    }

    if (Command.UserModeCrash.ProgramName) {
        Command.UserModeCrash.ProgramName += (UINT64)Buffer;
    }

    InitializeManualCrash(&CrashOpaque, &CrashOpaqueSize);
    Command.Dump.Buffer = (UINT64)CrashOpaque;
    Command.Dump.Size = CrashOpaqueSize;

    S2EInvokePlugin("WindowsCrashMonitor", &Command, sizeof(Command));

err:
    return Status;
}

NTSTATUS S2EIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    ULONG FunctionCode;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesReturned;
    PVOID Buffer;
    ULONG InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    BytesReturned = 0;

    Buffer = Irp->AssociatedIrp.SystemBuffer;
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    switch (FunctionCode) {
        case IOCTL_S2E_REGISTER_MODULE:
            Status = S2EIoCtlRegisterModule(Buffer, InputBufferLength);
            break;

        case IOCTL_S2E_WINDOWS_USERMODE_CRASH:
            Status = S2EIoCtlUserModeCrash(Buffer, InputBufferLength);
            break;

        case IOCTL_S2E_CRASH_KERNEL:
            KeBugCheck(0xDEADDEAD);
            break;

        default:
            Status = STATUS_NOT_SUPPORTED;
            break;
    }

    if (Status != STATUS_PENDING) {
        Irp->IoStatus.Information = BytesReturned;
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32DeviceName;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    LOG("Unloading s2e.sys\n");

    RtlInitUnicodeString(&Win32DeviceName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&Win32DeviceName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    MonitoringDeinitialize();
    FilterUnregister();
}

VOID BugCheckCallback(PVOID Buffer, ULONG Length)
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    S2EKillState(0, "BSOD - s2e.sys detected kernel crash");
}
