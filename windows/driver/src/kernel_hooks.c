///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <ntddk.h>
#include <ntstrsafe.h>
#include <s2e/s2e.h>
#include <s2e/WindowsMonitor.h>
#include <s2e/GuestCodePatching.h>
#include "kernel_structs.h"
#include "log.h"

void* _ReturnAddress(VOID);

#pragma intrinsic(_ReturnAddress)

//#define DEBUG_KERNEL_HOOK

typedef enum _OB_OPEN_REASON
{
    ObCreateHandle = 0,
    ObOpenHandle = 1,
    ObDuplicateHandle = 2,
    ObInheritHandle = 3,
    ObMaxOpenReason = 4
} OB_OPEN_REASON;

/**
 * ObpCreateHandle has 10 parameters, whose type we don't know.
 * Set the types to UINT_PTR to make sure that there is no truncation.
 */
typedef NTSTATUS(*OBPCREATEHANDLE)(
    OB_OPEN_REASON OpenReason,
    PVOID Object,
    UINT_PTR Type,
    UINT_PTR AccessState,
    UINT_PTR AdditionalReferences,
    UINT_PTR HandleAttributes,
    UINT_PTR Context,
    UINT_PTR AccessMode,
    PVOID *pReturnedObject,
    PHANDLE ReturnedHandle
);

static NTSTATUS ObpCreateHandleHook(
    OB_OPEN_REASON OpenReason,
    PVOID Object,
    UINT_PTR Type,
    UINT_PTR AccessState,
    UINT_PTR AdditionalReferences,
    UINT_PTR HandleAttributes,
    UINT_PTR Context,
    UINT_PTR AccessMode,
    PVOID *pReturnedObject,
    PHANDLE ReturnedHandle
)
{
    NTSTATUS Ret;
    PEPROCESS Process = NULL;
    NTSTATUS Result;
    HANDLE ProcessId;
    OBPCREATEHANDLE Original = (OBPCREATEHANDLE)(UINT_PTR)g_kernelStructs.ObpCreateHandle;

    Ret = Original(OpenReason, Object, Type, AccessState, AdditionalReferences, HandleAttributes,
            Context, AccessMode, pReturnedObject, ReturnedHandle);

    if ((Ret != STATUS_SUCCESS) || !ReturnedHandle) {
        return Ret;
    }

    Result = ObReferenceObjectByHandle(*ReturnedHandle, READ_CONTROL, *PsProcessType, KernelMode, &Process, NULL);
    if (Result != STATUS_SUCCESS) {
        return Ret;
    }

    ProcessId = PsGetProcessId(Process);
    ObDereferenceObject(Process);

#ifdef DEBUG_KERNEL_HOOK
    LOG("ObpCreateHandleHook got a process object! handle=%p pid=%p cr3=%p\n",
        *ReturnedHandle, ProcessId, __readcr3());
#endif

    {
        S2E_WINMON2_COMMAND Cmd;
        Cmd.Command = PROCESS_HANDLE_CREATE;
        Cmd.ProcessHandle.SourceProcessId = (UINT_PTR)PsGetCurrentProcessId();
        Cmd.ProcessHandle.TargetProcessId = (UINT_PTR)ProcessId;
        Cmd.ProcessHandle.Handle = (UINT_PTR)*ReturnedHandle;
        S2EInvokePlugin("WindowsMonitor", &Cmd, sizeof(Cmd));
    }

    return Ret;
}

/**********************************/

typedef NTSTATUS(*MMACCESSFAULT)(
    ULONG_PTR FaultStatus,
    PVOID VirtualAddress,
    KPROCESSOR_MODE PreviousMode,
    PVOID TrapInformation
);

NTSTATUS MmAccessFault(
    ULONG_PTR FaultStatus,
    PVOID VirtualAddress,
    KPROCESSOR_MODE PreviousMode,
    PVOID TrapInformation
)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    MMACCESSFAULT Original = (MMACCESSFAULT)(UINT_PTR)g_kernelStructs.MmAccessFault;

    Ret = Original(FaultStatus, VirtualAddress, PreviousMode, TrapInformation);

    Command.Command = ACCESS_FAULT;
    Command.AccessFault.Address = (UINT_PTR)VirtualAddress;
    Command.AccessFault.AccessMode = (BOOLEAN)PreviousMode;
    Command.AccessFault.StatusCode = (UINT64)(UINT32)Ret;
    Command.AccessFault.TrapInformation = (UINT_PTR)TrapInformation;
    Command.AccessFault.ReturnAddress = (UINT_PTR)_ReturnAddress();

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));

    return Ret;
}

/**********************************/
typedef NTSTATUS(*NTALLOCATEVIRTUALMEMORY)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
);

static NTSTATUS NtAllocateVirtualMemory(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    NTALLOCATEVIRTUALMEMORY Original = (NTALLOCATEVIRTUALMEMORY)(UINT_PTR)g_kernelStructs.NtAllocateVirtualMemory;

    Ret = Original(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    //XXX: validate the pointers
#ifdef DEBUG_KERNEL_HOOK
    LOG("%s ProcessHandle: %p BaseAddress: %p Size: %#x",
        __FUNCTION__, ProcessHandle,
        BaseAddress ? *BaseAddress : 0,
        RegionSize ? *RegionSize : 0);
#endif

    try {
        Command.Command = ALLOCATE_VIRTUAL_MEMORY;
        Command.AllocateVirtualMemory.Status = Ret;
        Command.AllocateVirtualMemory.ProcessHandle = (UINT_PTR)ProcessHandle;
        Command.AllocateVirtualMemory.BaseAddress = (UINT_PTR)(BaseAddress ? *BaseAddress : 0);
        Command.AllocateVirtualMemory.Size = RegionSize ? *RegionSize : 0;
        Command.AllocateVirtualMemory.AllocationType = AllocationType;
        Command.AllocateVirtualMemory.Protection = Protect;
        S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("%s EXCEPTION ProcessHandle: %p BaseAddress: %p Size: %#x",
            __FUNCTION__, ProcessHandle, BaseAddress, RegionSize);
    }

    return Ret;
}

/**********************************/

typedef NTSTATUS(*NTFREEVIRTUALMEMORY)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
);

NTSTATUS NtFreeVirtualMemory(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    NTFREEVIRTUALMEMORY Original = (NTFREEVIRTUALMEMORY)(UINT_PTR)g_kernelStructs.NtFreeVirtualMemory;

    Ret = Original(ProcessHandle, BaseAddress, RegionSize, FreeType);

#ifdef DEBUG_KERNEL_HOOK
    LOG("%s ProcessHandle: %p BaseAddress: %p Size: %#x",
        __FUNCTION__, ProcessHandle,
        BaseAddress ? *BaseAddress : 0,
        RegionSize ? *RegionSize : 0);
#endif

    try {
        Command.Command = FREE_VIRTUAL_MEMORY;
        Command.FreeVirtualMemory.Status = Ret;
        Command.FreeVirtualMemory.ProcessHandle = (UINT_PTR)ProcessHandle;
        Command.FreeVirtualMemory.BaseAddress = (UINT_PTR)(BaseAddress ? *BaseAddress : 0);
        Command.FreeVirtualMemory.Size = RegionSize ? *RegionSize : 0;
        Command.FreeVirtualMemory.FreeType = FreeType;
        S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("%s EXCEPTION ProcessHandle: %p BaseAddress: %p Size: %#x",
        __FUNCTION__, ProcessHandle,
        BaseAddress, RegionSize);
    }

    return Ret;
}

/**********************************/

typedef NTSTATUS(*NTPROTECTVIRTUALMEMORY)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection);

NTSTATUS NtProtectVirtualMemory(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    NTPROTECTVIRTUALMEMORY Original = (NTPROTECTVIRTUALMEMORY)(UINT_PTR)g_kernelStructs.NtProtectVirtualMemory;

    Ret = Original(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

#ifdef DEBUG_KERNEL_HOOK
    LOG("%s ProcessHandle: %p BaseAddress: %p Size: %#x",
        __FUNCTION__, ProcessHandle,
        BaseAddress ? *BaseAddress : 0,
        NumberOfBytesToProtect ? *NumberOfBytesToProtect : 0);
#endif

    try {
        Command.Command = PROTECT_VIRTUAL_MEMORY;
        Command.ProtectVirtualMemory.Status = Ret;
        Command.ProtectVirtualMemory.ProcessHandle = (UINT_PTR)ProcessHandle;
        Command.ProtectVirtualMemory.BaseAddress = (UINT_PTR)(BaseAddress ? *BaseAddress : 0);
        Command.ProtectVirtualMemory.Size = NumberOfBytesToProtect ? *NumberOfBytesToProtect : 0;
        Command.ProtectVirtualMemory.OldProtection = OldAccessProtection ? *OldAccessProtection : 0;
        Command.ProtectVirtualMemory.NewProtection = NewAccessProtection;
        S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("%s EXCEPTION ProcessHandle: %p BaseAddress: %p Size: %#p",
            __FUNCTION__, ProcessHandle, BaseAddress, NumberOfBytesToProtect);
    }
    return Ret;
}

/**********************************/

typedef NTSTATUS(*NTMAPVIEWOFSECTION)(
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  SECTION_INHERIT InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect
);

NTSTATUS NtMapViewOfSection(
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  SECTION_INHERIT InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect
)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    NTMAPVIEWOFSECTION Original = (NTMAPVIEWOFSECTION)(UINT_PTR)g_kernelStructs.NtMapViewOfSection;

    Ret = Original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
                   CommitSize, SectionOffset, ViewSize, InheritDisposition,
                   AllocationType, Win32Protect);

#ifdef DEBUG_KERNEL_HOOK
    LOG("%s SectionHandle: %p ProcessHandle: %p BaseAddress: %p ViewSize: %#x",
        __FUNCTION__, SectionHandle, ProcessHandle,
        BaseAddress ? *BaseAddress : 0,
        ViewSize ? *ViewSize : 0);
#endif

    try {
        Command.Command = MAP_VIEW_OF_SECTION;
        Command.MapViewOfSection.Status = Ret;
        Command.MapViewOfSection.ProcessHandle = (UINT_PTR)ProcessHandle;
        Command.MapViewOfSection.BaseAddress = (UINT_PTR)(BaseAddress ? *BaseAddress : 0);
        Command.MapViewOfSection.Size = ViewSize ? *ViewSize : 0;
        Command.MapViewOfSection.AllocationType = AllocationType;
        Command.MapViewOfSection.Win32Protect = Win32Protect;
        S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("%s EXCEPTION SectionHandle: %p ProcessHandle: %p BaseAddress: %p ViewSize: %#x",
        __FUNCTION__, SectionHandle, ProcessHandle,
        BaseAddress, ViewSize);
    }

    return Ret;
}

/**********************************/

typedef NTSTATUS(*MIUNMAPVIEWOFSECTION)(
  PEPROCESS Process,
  PVOID BaseAddress,
  UINT_PTR Unk
);

NTSTATUS MiUnmapViewOfSection(
  PEPROCESS Process,
  PVOID BaseAddress,
  UINT_PTR Unk
)
{
    NTSTATUS Ret;
    S2E_WINMON2_COMMAND Command;
    MIUNMAPVIEWOFSECTION Original = (MIUNMAPVIEWOFSECTION)(UINT_PTR)g_kernelStructs.MiUnmapViewOfSection;

    Ret = Original(Process, BaseAddress, Unk);

#ifdef DEBUG_KERNEL_HOOK
    LOG("%s Process: %p Pid: %p BaseAddress: %p",
        __FUNCTION__, Process, PsGetProcessId(Process), BaseAddress);
#endif

    Command.Command = UNMAP_VIEW_OF_SECTION;
    Command.UnmapViewOfSection.Status = Ret;
    Command.UnmapViewOfSection.EProcess = (UINT_PTR)Process;
    Command.UnmapViewOfSection.BaseAddress = (UINT_PTR)BaseAddress;
    Command.UnmapViewOfSection.Pid = (UINT_PTR)PsGetProcessId(Process);
    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));

    return Ret;
}

VOID InitializeKernelHooks(VOID)
{
    if (g_kernelStructs.ObpCreateHandle) {
        GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.ObpCreateHandle, (UINT_PTR)ObpCreateHandleHook);
    } else {
        S2EKillState(0, "no ObpCreateHandle hook available");
    }

    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.MmAccessFault, (UINT_PTR)MmAccessFault);
    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.NtAllocateVirtualMemory, (UINT_PTR)NtAllocateVirtualMemory);
    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.NtFreeVirtualMemory, (UINT_PTR)NtFreeVirtualMemory);
    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.NtProtectVirtualMemory, (UINT_PTR)NtProtectVirtualMemory);
    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.NtMapViewOfSection, (UINT_PTR)NtMapViewOfSection);
    GuestCodePatchingRegisterDirectKernelHook(g_kernelStructs.MiUnmapViewOfSection, (UINT_PTR)MiUnmapViewOfSection);
}
