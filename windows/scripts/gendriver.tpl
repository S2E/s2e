///
/// Copyright (C) 2014-2017, Cyberhaven
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/* Automatically generated code. Do not edit. */

#include <ntddk.h>
#include <ntimage.h>
#include <Aux_klib.h>
#include <s2e/s2e.h>
#include "winmonitor.h"
#include "kernel_structs.h"
#include "log.h"

{% for d in data %}
static REGISTER_KERNEL_STRUCTS Handler{{d.checksum | hex}};
{% endfor %}

REGISTER_KERNEL_STRUCTS_HANDLERS g_KernelStructHandlers [] = {
{% for d in data %}
    {% if d.bits == 64 %}
    #if defined(_AMD64_)
    {% else %}
    #if defined(_X86_)
    {% endif %}
    { {{d.checksum | hex}}, &Handler{{d.checksum | hex}} }, /* {{d.version}} - {{d.bits}}*/
    #endif
{% endfor %}
};

{% for d in data %}

{% if d.bits == 64 %}
#if defined(_AMD64_)
{% else %}
#if defined(_X86_)
{% endif %}

/* Version {{d.version}}, {{d.bits}}-bits */
static VOID Handler{{d.checksum | hex}}(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version {{d.version}} ({{d.bits}}-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = {{d.checksum | hex}};
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = {{d.IopDeleteDriver | hex}}; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = {% if d.PerfLogImageUnload == 0 %}0{%else%}(UINT_PTR)({{d.PerfLogImageUnload | hex}} - KernelNativeBase + KernelLoadBase){%endif%};

    {%- if d.bits == 64 %}

    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    {%- else %}
    {%- if d.version[0] == '5' %}

    pKpcr = (KPCR*) 0xffdff000;
    {%- else %}
    {% if d.KiInitialPCR == 0 %}
    #error KiInitialPCR cannot be null
    {% endif %}
    pKpcr = (KPCR*) ({{d.KiInitialPCR | hex}} - KernelNativeBase + KernelLoadBase);
    {%- endif %}
    {%- endif %}

    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->{{ 'CurrentPrcb' if d.bits == 64 else 'Prcb' }};

    Command.Structs.EThreadSegment = {{ 'R_GS' if d.bits == 64 else 'R_FS' }};

    {%- if d.version[0] == '5' %}
    Command.Structs.EThreadSegmentOffset = {{d._KPCR_PrcbData | hex}} + {{d._KPRCB_CurrentThread | hex}};
    {%- else %}
    Command.Structs.EThreadSegmentOffset = {{d._KPCR_Prcb | hex}} + {{d._KPRCB_CurrentThread | hex}};
    {%- endif %}

    Command.Structs.EThreadStackBaseOffset = {{d._KTHREAD_StackBase | hex}};
    Command.Structs.EThreadStackLimitOffset = {{d._KTHREAD_StackLimit | hex}};
    Command.Structs.EThreadProcessOffset = {{d._KTHREAD_Process | hex}};
    Command.Structs.EThreadCid = {{d._ETHREAD_Cid | hex}};

    Command.Structs.EProcessUniqueIdOffset = {{d._EPROCESS_UniqueProcessId | hex}};
    Command.Structs.EProcessCommitChargeOffset = {{d._EPROCESS_CommitCharge | hex}};
    Command.Structs.EProcessVirtualSizeOffset = {{d._EPROCESS_VirtualSize | hex}};
    Command.Structs.EProcessPeakVirtualSizeOffset = {{d._EPROCESS_PeakVirtualSize | hex}};
    Command.Structs.EProcessCommitChargePeakOffset = {{d._EPROCESS_CommitChargePeak | hex}};

    Command.Structs.EProcessVadRootOffset = {{d._EPROCESS_VadRoot | hex}};

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + {{d._KPRCB_DpcStack | hex}};
    Command.Structs.DPCStackSize = {{ '24 * 1024' if d.bits == 64 else '0x3000' }};

    Command.Structs.PsLoadedModuleList = (UINT_PTR)({{d.PsLoadedModuleList | hex}} - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)({{d.PsActiveProcessHead | hex}} - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = {{d._EPROCESS_ActiveProcessLinks | hex}};
    g_kernelStructs.EProcessThreadListHeadOffset = {{d._EPROCESS_ThreadListHead | hex}};
    g_kernelStructs.EThreadThreadListEntry = {{d._ETHREAD_ThreadListEntry | hex}};

    g_kernelStructs.ObpCreateHandle = {{d.ObpCreateHandle | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = {{d.MmAccessFault | hex}} - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = {{d.NtAllocateVirtualMemory | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = {{d.NtFreeVirtualMemory | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = {{d.NtProtectVirtualMemory | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = {{d.NtMapViewOfSection | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = {{d.NtUnmapViewOfSection | hex}} - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = {{d.MiUnmapViewOfSection | hex}} - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx = {{d.NtUnmapViewOfSectionEx | hex}} - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = {{d.KeBugCheck2 | hex}}; //KeBugCheck2

    {%- if d.version[0] == '5' %}

    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + {{d._KPCR_KdVersionBlock | hex}});
    {%- endif %}

    Command.Structs.KdDebuggerDataBlock = {{d.KdDebuggerDataBlock | hex}};
    g_kernelStructs.KdCopyDataBlock = {{d.KdCopyDataBlock | hex}};
    g_kernelStructs.KdpDataBlockEncoded = {{d.KdpDataBlockEncoded | hex}};

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + {{d._KPRCB_ProcessorState | hex}});

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif

{% endfor %}
