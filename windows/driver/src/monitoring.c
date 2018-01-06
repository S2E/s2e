///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntifs.h>
#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>
#include "kernel_structs.h"
#include "kernel_functions.h"
#include "log.h"

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);

static VOID OnThreadNotification(
    IN HANDLE ProcessId,
    IN HANDLE ThreadId,
    IN BOOLEAN Create
)
{
    PETHREAD Thread;
    NTSTATUS Status;
    S2E_WINMON2_COMMAND Command;

    LOG("caught thread %s pid=%#x tid=%#x create=%d",
        Create ? "creation" : "termination", ProcessId, ThreadId, Create);

    //XXX: fails when create is true. Maybe the thread wasn't fully inited yet.
    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status)) {
        LOG("PsLookupThreadByThreadId failed with %#x", Status);
        Thread = NULL;
    }

    Command.Command = Create ? THREAD_CREATE : THREAD_EXIT;
    Command.Thread.ProcessId = (UINT_PTR)ProcessId;
    Command.Thread.ThreadId = (UINT_PTR)ThreadId;
    Command.Thread.EThread = (UINT_PTR)Thread;
    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));

    if (Thread) {
        ObDereferenceObject(Thread);
    }
}

static VOID OnProcessNotification(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    PEPROCESS Process;
    NTSTATUS Status;
    CHAR *ImageFileName;
    S2E_WINMON2_COMMAND Command;

    LOG("caught process %s pid=%p parent=%p\n",
        Create ? "creation" : "termination", ProcessId, ParentId);

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        S2EKillState(0, "PsLookupProcessByProcessId failed");
    }

    ImageFileName = g_pGetProcessImageFileName(Process);

    LOG("process image %s\n", ImageFileName);

    ObDereferenceObject(Process);

    Command.Process.EProcess = (UINT64)Process;
    Command.Process.ProcessId = (UINT64)ProcessId;
    Command.Process.ParentProcessId = (UINT64)ParentId;
    strncpy(Command.Process.ImageFileName, ImageFileName, sizeof(Command.Process.ImageFileName) - 1);

    Command.Command = Create ? LOAD_PROCESS : UNLOAD_PROCESS;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

/**
 * The operating system calls this routine to notify the driver when a driver image or a user image
 * (for example, a DLL or EXE) is mapped into virtual memory. This call occurs after the image is
 * mapped and before execution of the image starts.
 *
 * When the main executable image for a newly created process is loaded,
 * the load-image notify routine runs in the context of the new process.
 */
static VOID OnImageLoad(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    S2E_WINMON2_COMMAND Command;

    LOG("detected image load pid=%p addr=%p size=%#x %wZ kernel=%d allpids=%d\n",
        ProcessId,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        FullImageName,
        ImageInfo->SystemModeImage,
        ImageInfo->ImageMappedToAllPids);

    if (ImageInfo->SystemModeImage) {
        //Ignore drivers for now, we load them differently
        return;
    }

    Command.Command = LOAD_IMAGE;
    Command.Module2.LoadBase = (UINT_PTR)ImageInfo->ImageBase;
    Command.Module2.Size = ImageInfo->ImageSize;
    Command.Module2.Pid = (UINT64)ProcessId;
    Command.Module2.UnicodeModulePath = (UINT_PTR)FullImageName->Buffer;
    Command.Module2.UnicodeModulePathSizeInBytes = FullImageName->Length;
    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

VOID MonitoringInitialize(VOID)
{
    NTSTATUS Status;

    Status = PsSetCreateProcessNotifyRoutine(OnProcessNotification, FALSE);
    if (!NT_SUCCESS(Status)) {
        LOG("could not register process watchdog\n");
    }

    Status = PsSetCreateThreadNotifyRoutine(OnThreadNotification);
    if (!NT_SUCCESS(Status)) {
        LOG("could not register thread notification routine\n");
    }

    Status = PsSetLoadImageNotifyRoutine(OnImageLoad);
    if (!NT_SUCCESS(Status)) {
        S2EKillState(0, "could not register image loading notification routine\n");
    }
}

VOID MonitoringDeinitialize(VOID)
{
    PsSetCreateProcessNotifyRoutine(OnProcessNotification, TRUE);
    PsRemoveCreateThreadNotifyRoutine(OnThreadNotification);
    PsRemoveLoadImageNotifyRoutine(OnImageLoad);
}
