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

#include "../log.h"
#include "../kernel_functions.h"
#include "../adt/strings.h"
#include "process.h"

#define TAG_PROCESS 'proc'

NTSTATUS ProcessOpenHandle(_In_ ULONG ProcessID, _Out_ PHANDLE Handle)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    CLIENT_ID ClientId = { 0 };
    ClientId.UniqueProcess = UlongToHandle(ProcessID);
    Status = ZwOpenProcess(Handle, PROCESS_ALL_ACCESS, &oa, &ClientId);
    if (!NT_SUCCESS(Status)) {
        LOG("unable to get handle for process %u: %08x\n", ProcessID, Status);
    }

    return Status;
}

NTSTATUS ProcessQueryInfo(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS Class, _Out_ PVOID *Data)
{
    NTSTATUS Status;
    ULONG ReturnedLength;
    PVOID Buffer = NULL;

    *Data = NULL;

    Status = ZwQueryInformationProcess(ProcessHandle,
                                       Class, NULL, 0, &ReturnedLength);

    if (Status != STATUS_INFO_LENGTH_MISMATCH) {
        LOG("Could not query process information class %#x (%#x)\n", Class, Status);
        goto err;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, ReturnedLength, TAG_PROCESS);
    if (!Buffer) {
        LOG("Could not allocate memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Status = ZwQueryInformationProcess(ProcessHandle,
                                       Class, Buffer, ReturnedLength, &ReturnedLength);

    if (!NT_SUCCESS(Status)) {
        LOG("Could not query process information class %#x (%#x)\n", Class, Status);
        goto err;
    }

    *Data = Buffer;

    return Status;

err:
    if (Buffer) {
        ExFreePoolWithTag(Buffer, TAG_PROCESS);
    }

    return Status;
}

NTSTATUS ProcessGetImageNameFromHandle(_In_ HANDLE ProcessHandle, _Inout_ PUNICODE_STRING ProcessImageName)
{
    NTSTATUS Status;
    PVOID Buffer;
    PUNICODE_STRING ImageName;

    Status = ProcessQueryInfo(ProcessHandle, ProcessImageFileName, &Buffer);
    if (!NT_SUCCESS(Status)) {
        goto err;
    }

    ImageName = (PUNICODE_STRING)Buffer;

    ProcessImageName->MaximumLength = ImageName->MaximumLength;
    Status = StringAllocateUnicode(ProcessImageName);
    if (!NT_SUCCESS(Status)) {
        goto err;
    }

    RtlCopyUnicodeString(ProcessImageName, ImageName);

err:
    if (Buffer) {
        ExFreePoolWithTag(Buffer, TAG_PROCESS);
    }

    return Status;
}

NTSTATUS ProcessGetImageNameFromPid(_In_ ULONG ProcessId, _Inout_ PUNICODE_STRING ProcessImageName)
{
    NTSTATUS Status;
    HANDLE Handle = INVALID_HANDLE_VALUE;

    Status = ProcessOpenHandle(ProcessId, &Handle);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not open process handle (%#x)\n", Status);
        goto exit;
    }

    Status = ProcessGetImageNameFromHandle(Handle, ProcessImageName);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get image name from handle (%#x)\n", Status);
        goto exit;
    }

exit:
    if (Handle != INVALID_HANDLE_VALUE) {
        ZwClose(Handle);
    }

    return Status;
}

NTSTATUS ProcessGetImageName(_In_ PEPROCESS Process, _Inout_ PUNICODE_STRING ProcessImageName)
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;

    Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, MAXIMUM_ALLOWED, NULL, KernelMode, &ProcessHandle);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not open object: %#x\n", Status);
        goto err;
    }

    Status = ProcessGetImageNameFromHandle(ProcessHandle, ProcessImageName);

err:
    if (ProcessHandle) {
        ZwClose(ProcessHandle);
    }

    return Status;
}
