///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <fltKernel.h>

extern "C"
{
#include <s2e/s2e.h>
#include <s2e/GuestCodePatching.h>

#include "../log.h"
#include "faultinj.h"
#include "apis.h"
}

#include "faultinj.hpp"

extern "C"
{
    NTSTATUS S2EHook_FltAllocateContext(
        _In_ PFLT_FILTER Filter,
        _In_ FLT_CONTEXT_TYPE ContextType,
        _In_ SIZE_T ContextSize,
        _In_ POOL_TYPE PoolType,
        _Out_ PFLT_CONTEXT *ReturnedContext
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "FltAllocateContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltAllocateContext,
            Filter, ContextType, ContextSize, PoolType, ReturnedContext
        );
    }

    PFLT_DEFERRED_IO_WORKITEM S2EHook_FltAllocateDeferredIoWorkItem(void)
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<PFLT_DEFERRED_IO_WORKITEM>(
            CallSite, "FltAllocateDeferredIoWorkItem", FALSE, nullptr, &FltAllocateDeferredIoWorkItem);
    }

    NTSTATUS S2EHook_FltBuildDefaultSecurityDescriptor(
        _Out_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
        _In_ ACCESS_MASK DesiredAccess
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
            UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
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
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "FltSetStreamHandleContext", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltSetStreamHandleContext,
            Instance, FileObject, Operation, NewContext, OldContext
        );
    }

    NTSTATUS S2EHook_FltStartFiltering(
        _In_ PFLT_FILTER Filter
    )
    {
        UINT_PTR CallSite = (UINT_PTR)_ReturnAddress();
        return FaultInjTemplate1<NTSTATUS>(
            CallSite, "FltStartFiltering", FALSE, STATUS_INSUFFICIENT_RESOURCES, &FltStartFiltering,
            Filter
        );
    }

    const S2E_HOOK g_kernelFltHooks[] = {
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltAllocateContext", (UINT_PTR)S2EHook_FltAllocateContext },
        {
            (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltAllocateDeferredIoWorkItem",
            (UINT_PTR)S2EHook_FltAllocateDeferredIoWorkItem
        },
        {
            (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltBuildDefaultSecurityDescriptor",
            (UINT_PTR)S2EHook_FltBuildDefaultSecurityDescriptor
        },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltClose", (UINT_PTR)S2EHook_FltClose },
        {
            (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltCreateCommunicationPort", (UINT_PTR)S2EHook_FltCreateCommunicationPort
        },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltCreateFileEx", (UINT_PTR)S2EHook_FltCreateFileEx },
        {
            (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltGetDestinationFileNameInformation",
            (UINT_PTR)S2EHook_FltGetDestinationFileNameInformation
        },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltGetFileNameInformation", (UINT_PTR)S2EHook_FltGetFileNameInformation },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltGetStreamContext", (UINT_PTR)S2EHook_FltGetStreamContext },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltGetStreamHandleContext", (UINT_PTR)S2EHook_FltGetStreamHandleContext },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltParseFileName", (UINT_PTR)S2EHook_FltParseFileName },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltQueryInformationFile", (UINT_PTR)S2EHook_FltQueryInformationFile },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltQuerySecurityObject", (UINT_PTR)S2EHook_FltQuerySecurityObject },
        {
            (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltQueueDeferredIoWorkItem", (UINT_PTR)S2EHook_FltQueueDeferredIoWorkItem
        },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltRegisterFilter", (UINT_PTR)S2EHook_FltRegisterFilter },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltSendMessage", (UINT_PTR)S2EHook_FltSendMessage },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltSetStreamContext", (UINT_PTR)S2EHook_FltSetStreamContext },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltSetStreamHandleContext", (UINT_PTR)S2EHook_FltSetStreamHandleContext },
        { (UINT_PTR)"fltmgr.sys", (UINT_PTR)"FltStartFiltering", (UINT_PTR)S2EHook_FltStartFiltering },
        { 0,0,0 }
    };
}
