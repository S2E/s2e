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

#include <ntifs.h>
#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>
#include "kernel_structs.h"
#include "kernel_functions.h"
#include "utils/process.h"
#include "log.h"
#include "adt/strings.h"

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
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    UNICODE_STRING ProcessImageName = { 0 };

    LOG("caught process %s pid=%p parent=%p\n",
        Create ? "creation" : "termination", ProcessId, ParentId);

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not lookup process (%#)\n", Status);
        goto err;
    }

    Status = ProcessGetImageNameFromPid(HandleToULong(ProcessId), &ProcessImageName);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get process image name\n");
        goto err;
    }

    LOG("Process image %wZ\n", &ProcessImageName);

    WinMon2LoadUnloadProcess(Create, &ProcessImageName, HandleToULong(ProcessId),
                             HandleToULong(ParentId), (UINT_PTR)Process);

err:
    if (Process) {
        ObDereferenceObject(Process);
    }

    StringFree(&ProcessImageName);
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
