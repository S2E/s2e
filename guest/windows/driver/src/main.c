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
#include <wdmsec.h>

#include <s2e/s2e.h>
#include <s2ectl.h>
#include "crash.h"

#include <s2e/StaticStateMerger.h>
#include <s2e/WindowsCrashMonitor.h>
#include <s2e/GuestCodeHooking.h>

#include "kernel_functions.h"
#include "kernel_hooks.h"
#include "kernel_structs.h"
#include "monitoring.h"
#include "winmonitor.h"
#include "filter.h"

#include "adt/strings.h"
#include "config/config.h"
#include "faultinj/faultinj.h"

#include "log.h"

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE) static DRIVER_DISPATCH S2EOpen;
_Dispatch_type_(IRP_MJ_CLOSE) static DRIVER_DISPATCH S2EClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) static DRIVER_DISPATCH S2EIoControl;

#define NT_DEVICE_NAME          L"\\Device\\S2EDriver"
#define DOS_DEVICE_NAME         L"\\DosDevices\\S2EDriver"

PDEVICE_OBJECT g_DeviceObject = NULL;

S2E_CONFIG g_config;

static NTSTATUS GetOSVersion(RTL_OSVERSIONINFOEXW *Version)
{
    NTSTATUS Status;

    Version->dwOSVersionInfoSize = sizeof(*Version);
    Status = RtlGetVersion((PRTL_OSVERSIONINFOW)Version);

    if (NT_SUCCESS(Status)) {
        LOG("Detected kernel version %d.%d.%d\n",
            Version->dwMajorVersion,
            Version->dwMinorVersion,
            Version->dwBuildNumber);
    }

    return Status;
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
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
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

    Status = GetOSVersion(&g_kernelStructs.Version);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get kernel version (%#x)\n", Status);
        goto err;
    }

    Status = ValidateS2E();
    if (!NT_SUCCESS(Status)) {
        LOG("Could not validate S2E (%#x)\n", Status);
        goto err;
    }
    S2EValidated = TRUE;

    Status = ConfigInit(&g_config);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not read S2E configuration from registry (%#x)\n", Status);
        goto err;
    }

    ConfigDump(&g_config);

    if (!ApiInitialize()) {
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

    if (g_config.FaultInjectionEnabled) {
        FaultInjectionInit();
    }

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

static NTSTATUS S2EOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp->FileObject->FsContext = NULL;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

static NTSTATUS S2EClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS NtStatus;
    PIO_STACK_LOCATION IrpSp;

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
        LOG("Invalid input length\n");
        Status = STATUS_INVALID_USER_BUFFER;
        goto err;
    }

    while (DriverName[NameLength] && (NameLength < 128 && (NameLength < InputBufferLength - 1))) {
        NameLength++;
    }

    DriverName[NameLength] = 0;
    LOG("IOCTL_S2E_REGISTER_MODULE (%s)", DriverName);

    // TODO: pass the driver name to the GuestCodeHooking plugin so that
    // driver API hooking could start.
    S2EKillState(0, "S2EIoCtlRegisterModule is not implemented, see code for comments");

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

static NTSTATUS S2EIoCtlSetConfig(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status;
    S2E_IOCTL_SET_CONFIG *Config = (S2E_IOCTL_SET_CONFIG*)Buffer;
    if (InputBufferLength < sizeof(*Config)) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    if (Config->Size < sizeof(*Config)) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    UINT64 NameSize = Config->Size - sizeof(*Config);

    if (NameSize == 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    // Make sure the input is null-terminated
    Config->Name[NameSize - 1] = 0;

    Status = ConfigSet(&g_config, Config->Name, Config->Value);

err:
    return Status;
}

static NTSTATUS S2EIoCtlInvokePlugin(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status;
    S2E_IOCTL_INVOKE_PLUGIN *Config = (S2E_IOCTL_INVOKE_PLUGIN*)Buffer;
    if (InputBufferLength < sizeof(*Config)) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    // Make sure there is no overflow by casting
    if ((UINT64)Config->DataOffset + (UINT64)Config->DataSize > (UINT64)InputBufferLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    if ((UINT64)Config->PluginNameOffset + (UINT64)Config->PluginNameSize > (UINT64)InputBufferLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    // Make sure plugin name is null-terminated
    PSTR PluginName = (PSTR)(((UINT_PTR)Config) + Config->PluginNameOffset);
    PluginName[Config->PluginNameSize - 1] = 0;

    UINT_PTR Data = ((UINT_PTR)Config) + Config->DataOffset;

    LOG("Invoking plugin %s with data size %#x\n", PluginName, Config->DataSize);
    Config->Result = S2EInvokePlugin(PluginName, (PVOID)Data, Config->DataSize);
    Status = STATUS_SUCCESS;

err:
    return Status;
}

static NTSTATUS S2EIoctlMakeSymbolic(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status;
    PSTR VariableName = NULL;
    S2E_IOCTL_MAKE_SYMBOLIC *Req = (S2E_IOCTL_MAKE_SYMBOLIC*)Buffer;
    if (InputBufferLength < sizeof(*Req)) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    try {
        ProbeForRead((PVOID)(UINT_PTR)Req->VariableNamePointer, Req->VariableNameSize, 1);
        ProbeForWrite((PVOID)(UINT_PTR)Req->DataPointer, Req->DataSize, 1);

        VariableName = StringDuplicateA((PVOID)(UINT_PTR)Req->VariableNamePointer, Req->VariableNameSize);
        if (!VariableName) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }

        S2EMakeSymbolic((PVOID)(UINT_PTR)Req->DataPointer, Req->DataSize, VariableName);

    } except (EXCEPTION_EXECUTE_HANDLER) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    Status = STATUS_SUCCESS;

err:
    if (VariableName) {
        ExFreePool(VariableName);
    }

    return Status;
}

static NTSTATUS S2EIoCtlGetPathId(_In_ PVOID Buffer, _In_ ULONG InputBufferLength)
{
    NTSTATUS Status;
    S2E_IOCTL_GET_PATH_ID *Req = (S2E_IOCTL_GET_PATH_ID*)Buffer;
    if (InputBufferLength < sizeof(*Req)) {
        Status = STATUS_INVALID_PARAMETER;
        goto err;
    }

    Req->PathId = S2EGetPathId();

    Status = STATUS_SUCCESS;

err:
    return Status;
}

static NTSTATUS S2EIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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
#pragma warning(push)
#pragma warning(disable: 28159)
            KeBugCheck(0xDEADDEAD);
#pragma warning(pop)
            break;

        case IOCTL_S2E_SET_CONFIG:
            Status = S2EIoCtlSetConfig(Buffer, InputBufferLength);
            break;

        case IOCTL_S2E_INVOKE_PLUGIN:
            Status = S2EIoCtlInvokePlugin(Buffer, InputBufferLength);
            if (NT_SUCCESS(Status)) {
                BytesReturned = InputBufferLength;
            }
            break;

        case IOCTL_S2E_MAKE_SYMBOLIC:
            Status = S2EIoctlMakeSymbolic(Buffer, InputBufferLength);
            break;

        case IOCTL_S2E_GET_PATH_ID:
            Status = S2EIoCtlGetPathId(Buffer, InputBufferLength);
            if (NT_SUCCESS(Status)) {
                BytesReturned = InputBufferLength;
            }
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

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32DeviceName;

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
