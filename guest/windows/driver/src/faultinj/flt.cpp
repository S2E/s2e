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

extern "C" {
#include <s2e/s2e.h>
#include <s2e/GuestCodeHooking.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C" {

NTSTATUS S2EHook_FltAllocateContext(
    _In_ PFLT_FILTER Filter,
    _In_ FLT_CONTEXT_TYPE ContextType,
    _In_ SIZE_T ContextSize,
    _In_ POOL_TYPE PoolType,
    _Out_ PFLT_CONTEXT *ReturnedContext
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltAllocateContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltAllocateContext,
        Filter, ContextType, ContextSize, PoolType, ReturnedContext
    );
}

PFLT_DEFERRED_IO_WORKITEM S2EHook_FltAllocateDeferredIoWorkItem(void)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<PFLT_DEFERRED_IO_WORKITEM>(
        CallSite, "FltAllocateDeferredIoWorkItem", FALSE, nullptr, &FltAllocateDeferredIoWorkItem);
}

NTSTATUS S2EHook_FltBuildDefaultSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltBuildDefaultSecurityDescriptor", FALSE, STATUS_INSUFFICIENT_RESOURCES,
        &FltBuildDefaultSecurityDescriptor,
        SecurityDescriptor, DesiredAccess);
}

NTSTATUS S2EHook_FltClose(
    _In_ HANDLE FileHandle
)
{
    if (g_config.FaultInjectionOverapproximate) {
        const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "FltClose", FALSE, STATUS_INSUFFICIENT_RESOURCES,
            &FltClose, FileHandle);
    } else {
        return FltClose(FileHandle);
    }
}

NTSTATUS S2EHook_FltCreateCommunicationPort(
    _In_ PFLT_FILTER Filter,
    _Out_ PFLT_PORT *ServerPort,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PVOID ServerPortCookie,
    _In_ PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
    _In_ PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback,
    _In_opt_ PFLT_MESSAGE_NOTIFY MessageNotifyCallback,
    _In_ LONG MaxConnections
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltCreateCommunicationPort", FALSE, STATUS_INSUFFICIENT_RESOURCES,
        &FltCreateCommunicationPort,
        Filter, ServerPort, ObjectAttributes, ServerPortCookie, ConnectNotifyCallback,
        DisconnectNotifyCallback, MessageNotifyCallback, MaxConnections);
}

NTSTATUS S2EHook_FltCreateFileEx(
    _In_ PFLT_FILTER Filter,
    _In_opt_ PFLT_INSTANCE Instance,
    _Out_ PHANDLE FileHandle,
    _Out_ PFILE_OBJECT *FileObject,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_opt_ PVOID EaBuffer,
    _In_ ULONG EaLength,
    _In_ ULONG Flags
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltCreateFileEx", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltCreateFileEx,
        Filter, Instance, FileHandle, FileObject, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
        EaBuffer, EaLength, Flags
    );
}

NTSTATUS S2EHook_FltGetDestinationFileNameInformation(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ HANDLE RootDirectory,
    _In_ PWSTR FileName,
    _In_ ULONG FileNameLength,
    _In_ FLT_FILE_NAME_OPTIONS NameOptions,
    _Out_ PFLT_FILE_NAME_INFORMATION *RetFileNameInformation
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltGetDestinationFileNameInformation", FALSE, STATUS_INSUFFICIENT_RESOURCES,
        &FltGetDestinationFileNameInformation,
        Instance, FileObject, RootDirectory, FileName, FileNameLength, NameOptions, RetFileNameInformation
    );
}

NTSTATUS S2EHook_FltGetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA CallbackData,
    _In_ FLT_FILE_NAME_OPTIONS NameOptions,
    _Out_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltGetFileNameInformation", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltGetFileNameInformation,
        CallbackData, NameOptions, FileNameInformation
    );
}

NTSTATUS S2EHook_FltGetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFLT_CONTEXT *Context
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltGetStreamContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltGetStreamContext,
        Instance, FileObject, Context
    );
}

NTSTATUS S2EHook_FltGetStreamHandleContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PFLT_CONTEXT *Context
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltGetStreamHandleContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltGetStreamHandleContext,
        Instance, FileObject, Context
    );
}

NTSTATUS S2EHook_FltParseFileName(
    _In_ PCUNICODE_STRING FileName,
    _Inout_ PUNICODE_STRING Extension,
    _Inout_ PUNICODE_STRING Stream,
    _Inout_ PUNICODE_STRING FinalComponent
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltParseFileName", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltParseFileName,
        FileName, Extension, Stream, FinalComponent
    );
}

NTSTATUS S2EHook_FltQueryInformationFile(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _Out_opt_ PULONG LengthReturned
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltQueryInformationFile", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltQueryInformationFile,
        Instance, FileObject, FileInformation, Length, FileInformationClass, LengthReturned
    );
}

NTSTATUS S2EHook_FltQuerySecurityObject(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ULONG Length,
    _Out_opt_ PULONG LengthNeeded
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltQuerySecurityObject", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltQuerySecurityObject,
        Instance, FileObject, SecurityInformation, SecurityDescriptor, Length, LengthNeeded
    );
}

NTSTATUS S2EHook_FltQueueDeferredIoWorkItem(
    _In_ PFLT_DEFERRED_IO_WORKITEM FltWorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_DEFERRED_IO_WORKITEM_ROUTINE WorkerRoutine,
    _In_ WORK_QUEUE_TYPE QueueType,
    _In_ PVOID Context
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltQueueDeferredIoWorkItem", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltQueueDeferredIoWorkItem,
        FltWorkItem, Data, WorkerRoutine, QueueType, Context
    );
}


NTSTATUS S2EHook_FltRegisterFilter(
    _In_ PDRIVER_OBJECT Driver,
    _In_ const FLT_REGISTRATION *Registration,
    _Out_ PFLT_FILTER *RetFilter
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltRegisterFilter", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltRegisterFilter,
        Driver, Registration, RetFilter
    );
}

NTSTATUS S2EHook_FltSendMessage(
    _In_ PFLT_FILTER Filter,
    _In_ PFLT_PORT *ClientPort,
    _In_ PVOID SenderBuffer,
    _In_ ULONG SenderBufferLength,
    _Out_opt_ PVOID ReplyBuffer,
    _Inout_ PULONG ReplyLength,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltSendMessage", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltSendMessage,
        Filter, ClientPort, SenderBuffer, SenderBufferLength, ReplyBuffer, ReplyLength, Timeout
    );
}

NTSTATUS S2EHook_FltSetStreamContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ FLT_SET_CONTEXT_OPERATION Operation,
    _In_ PFLT_CONTEXT NewContext,
    _Out_ PFLT_CONTEXT *OldContext
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltSetStreamContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltSetStreamContext,
        Instance, FileObject, Operation, NewContext, OldContext
    );
}

NTSTATUS S2EHook_FltSetStreamHandleContext(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ FLT_SET_CONTEXT_OPERATION Operation,
    _In_ PFLT_CONTEXT NewContext,
    _Out_opt_ PFLT_CONTEXT *OldContext
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltSetStreamHandleContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltSetStreamHandleContext,
        Instance, FileObject, Operation, NewContext, OldContext
    );
}

NTSTATUS S2EHook_FltStartFiltering(
    _In_ PFLT_FILTER Filter
)
{
    const UINT_PTR CallSite = reinterpret_cast<UINT_PTR>(_ReturnAddress());
    return FaultInjTemplate1<NTSTATUS>(
        CallSite, "FltStartFiltering", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltStartFiltering,
        Filter
    );
}

const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelFltHooks[] = {
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltAllocateContext", S2EHook_FltAllocateContext),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltAllocateDeferredIoWorkItem", S2EHook_FltAllocateDeferredIoWorkItem),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltBuildDefaultSecurityDescriptor", S2EHook_FltBuildDefaultSecurityDescriptor),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltClose", S2EHook_FltClose),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltCreateCommunicationPort", S2EHook_FltCreateCommunicationPort),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltCreateFileEx", S2EHook_FltCreateFileEx),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltGetDestinationFileNameInformation",
        S2EHook_FltGetDestinationFileNameInformation),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltGetFileNameInformation", S2EHook_FltGetFileNameInformation),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltGetStreamContext", S2EHook_FltGetStreamContext),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltGetStreamHandleContext", S2EHook_FltGetStreamHandleContext),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltParseFileName", S2EHook_FltParseFileName),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltQueryInformationFile", S2EHook_FltQueryInformationFile),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltQuerySecurityObject", S2EHook_FltQuerySecurityObject),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltQueueDeferredIoWorkItem", S2EHook_FltQueueDeferredIoWorkItem),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltRegisterFilter", S2EHook_FltRegisterFilter),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltSendMessage", S2EHook_FltSendMessage),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltSetStreamContext", S2EHook_FltSetStreamContext),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltSetStreamHandleContext", S2EHook_FltSetStreamHandleContext),
    S2E_KERNEL_FCN_HOOK("fltmgr.sys", "FltStartFiltering", S2EHook_FltStartFiltering),
    S2E_KERNEL_FCN_HOOK_END()
};

}
