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
    S2E_WINMON2_COMMAND Command = { 0 };

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

    // TODO: fix this to handle full process names
    // PsGetProcessImageFileName does not return the full path
    if (strncpy_s(Command.Process.ImageFileName, sizeof(Command.Process.ImageFileName),
                  ImageFileName, sizeof(Command.Process.ImageFileName))) {
        LOG("Could not copy process image name %s\n", ImageFileName);
        S2EKillState(0, "strncpy_s failed");
    }

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
    LOG("detected image load pid=%p addr=%p size=%#x %wZ kernel=%d allpids=%d\n",
        ProcessId,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        FullImageName,
        ImageInfo->SystemModeImage,
        ImageInfo->ImageMappedToAllPids);

    if (ImageInfo->SystemModeImage) {
        WinMon2LoadDriver(FullImageName, (UINT_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize);
    } else {
        WinMon2LoadImage(FullImageName, (UINT_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize, (UINT64)ProcessId);
    }
}

NTSTATUS MonitoringInitialize(VOID)
{
    NTSTATUS Status;

    Status = PsSetCreateProcessNotifyRoutine(OnProcessNotification, FALSE);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not register process watchdog\n");
        goto err;
    }

    Status = PsSetCreateThreadNotifyRoutine(OnThreadNotification);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not register thread notification routine\n");
        goto err;
    }

    Status = PsSetLoadImageNotifyRoutine(OnImageLoad);
    if (!NT_SUCCESS(Status)) {
        LOG("could not register image loading notification routine\n");
        goto err;
    }

err:
    return Status;
}

VOID MonitoringDeinitialize(VOID)
{
    PsSetCreateProcessNotifyRoutine(OnProcessNotification, TRUE);
    PsRemoveCreateThreadNotifyRoutine(OnThreadNotification);
    PsRemoveLoadImageNotifyRoutine(OnImageLoad);
}
