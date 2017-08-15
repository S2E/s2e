///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/* Automatically generated code. Do not edit. */
// Resharper disable all

#include <ntddk.h>
#include <ntimage.h>
#include <Aux_klib.h>
#include <s2e/s2e.h>
#include "winmonitor.h"
#include "kernel_structs.h"
#include "log.h"

static REGISTER_KERNEL_STRUCTS Handler0x752730;
static REGISTER_KERNEL_STRUCTS Handler0x557f4d;
static REGISTER_KERNEL_STRUCTS Handler0x204e7e;
static REGISTER_KERNEL_STRUCTS Handler0x6aa6c8;
static REGISTER_KERNEL_STRUCTS Handler0x3c2f88;
static REGISTER_KERNEL_STRUCTS Handler0x54b487;
static REGISTER_KERNEL_STRUCTS Handler0x55ce0c;
static REGISTER_KERNEL_STRUCTS Handler0x3c9503;
static REGISTER_KERNEL_STRUCTS Handler0x3c05d5;
static REGISTER_KERNEL_STRUCTS Handler0x2247c2;
static REGISTER_KERNEL_STRUCTS Handler0x3c88ac;
static REGISTER_KERNEL_STRUCTS Handler0x71fad2;
static REGISTER_KERNEL_STRUCTS Handler0x7f010a;

REGISTER_KERNEL_STRUCTS_HANDLERS g_KernelStructHandlers[] = {
        #if defined(_AMD64_)
        { 0x752730, &Handler0x752730 }, /* ['10', '0', '9926', '0'] - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x557f4d, &Handler0x557f4d }, /* ['6', '1', '7601', '22616'] - 64*/
    #endif
        #if defined(_X86_)
        { 0x204e7e, &Handler0x204e7e }, /* ['5', '1', '2600', '5512'] - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x6aa6c8, &Handler0x6aa6c8 }, /* ['6', '2', '9200', '16384'] - 64*/
    #endif
        #if defined(_X86_)
        { 0x3c2f88, &Handler0x3c2f88 }, /* ['6', '1', '7600', '16385'] - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x54b487, &Handler0x54b487 }, /* ['6', '1', '7600', '16385'] - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x55ce0c, &Handler0x55ce0c }, /* ['6', '1', '7601', '17514'] - 64*/
    #endif
        #if defined(_X86_)
        { 0x3c9503, &Handler0x3c9503 }, /* ['6', '1', '7600', '16385'] - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c05d5, &Handler0x3c05d5 }, /* ['6', '1', '7601', '17514'] - 32*/
    #endif
        #if defined(_X86_)
        { 0x2247c2, &Handler0x2247c2 }, /* ['5', '1', '2600', '5512'] - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c88ac, &Handler0x3c88ac }, /* ['6', '1', '7601', '17514'] - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x71fad2, &Handler0x71fad2 }, /* ['6', '3', '9600', '17031'] - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x7f010a, &Handler0x7f010a }, /* (10, 0, 15063, 0) - 64*/
    #endif
};

#if defined(_AMD64_)

/* Version ['10', '0', '9926', '0'], 64-bits */
static VOID Handler0x752730(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['10', '0', '9926', '0'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x752730;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x14052267c; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x140418ffc - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x628;

    Command.Structs.EProcessUniqueIdOffset = 0x2e8;
    Command.Structs.EProcessCommitChargeOffset = 0x4e8;
    Command.Structs.EProcessVirtualSizeOffset = 0x338;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x330;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4f0;

    Command.Structs.EProcessVadRootOffset = 0x5f8;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2dd0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140307ef0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x1402eaba0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2f0;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x480;
    g_kernelStructs.EThreadThreadListEntry = 0x690;

    g_kernelStructs.ObpCreateHandle = 0x1403f98e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x1400401e0 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140413d90 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x140417070 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1404133d0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140411e70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14040c15c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14040c220 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1401c31bc; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1402d5610;
    g_kernelStructs.KdCopyDataBlock = 0x1401bf990;
    g_kernelStructs.KdpDataBlockEncoded = 0x140323e02;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version ['6', '1', '7601', '22616'], 64-bits */
static VOID Handler0x557f4d(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7601', '22616'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x557f4d;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f2ed0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x140052ef4 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCid = 0x3b8;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;

    Command.Structs.EProcessVadRootOffset = 0x448;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x21c0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140244890 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140226590 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x14036ff80 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140080820 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036e140 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400607f0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x140390660 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1403919f0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1403900c4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14038fb70 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140167760; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401f00d0;
    g_kernelStructs.KdCopyDataBlock = 0x140107cf0;
    g_kernelStructs.KdpDataBlockEncoded = 0x140218122;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['5', '1', '2600', '5512'], 32-bits */
static VOID Handler0x204e7e(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['5', '1', '2600', '5512'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x204e7e;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4a1a4a; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = 0;
    pKpcr = (KPCR*)0xffdff000;
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x120 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x168;
    Command.Structs.EThreadStackLimitOffset = 0x1c;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x1ec;

    Command.Structs.EProcessUniqueIdOffset = 0x84;
    Command.Structs.EProcessCommitChargeOffset = 0xa8;
    Command.Structs.EProcessVirtualSizeOffset = 0xb0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xac;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1ec;

    Command.Structs.EProcessVadRootOffset = 0x11c;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x868;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x47cfc0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x483158 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x4dbccc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x445368 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x4c6dbe - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4d1400 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x4d6a08 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4d0480 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4d1296 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4d10d0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x421216; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x46eae0;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version ['6', '2', '9200', '16384'], 64-bits */
static VOID Handler0x6aa6c8(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '2', '9200', '16384'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x6aa6c8;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x14048dd40; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1404d2a50 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x398;

    Command.Structs.EProcessUniqueIdOffset = 0x2e0;
    Command.Structs.EProcessCommitChargeOffset = 0x4d8;
    Command.Structs.EProcessVirtualSizeOffset = 0x328;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x320;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4e0;

    Command.Structs.EProcessVadRootOffset = 0x590;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2dc0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x1402caa60 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140296c10 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2e8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x470;
    g_kernelStructs.EThreadThreadListEntry = 0x400;

    g_kernelStructs.ObpCreateHandle = 0x140448cf0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x1400b5620 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140475070 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400eb910 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x140471e80 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x14046d590 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1404023a8 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14046e790 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140174fa4; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x140273a90;
    g_kernelStructs.KdCopyDataBlock = 0x140171ea0;
    g_kernelStructs.KdpDataBlockEncoded = 0x1402808cb;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['6', '1', '7600', '16385'], 32-bits */
static VOID Handler0x3c2f88(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7600', '16385'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c2f88;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5721fb; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x485d37 - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*)(0x521c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x20 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCid = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x53f570 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x538658 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x611455 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45eb87 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x6096e6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47ccec - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63caf9 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x6361e3 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x658a4a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x635e7c - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d1b37; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x520be8;
    g_kernelStructs.KdCopyDataBlock = 0x4cfdba;
    g_kernelStructs.KdpDataBlockEncoded = 0x52e596;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version ['6', '1', '7600', '16385'], 64-bits */
static VOID Handler0x54b487(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7600', '16385'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54b487;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404e9f30; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x140050fb0 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCid = 0x3b0;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;

    Command.Structs.EProcessVadRootOffset = 0x448;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x21c0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x14023de50 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x14021fb30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x420;

    g_kernelStructs.ObpCreateHandle = 0x140367270 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14008bbe0 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140370d50 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400b3680 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14038b984 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140388c00 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1403881fc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140387ca0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140167da0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401e9070;
    g_kernelStructs.KdCopyDataBlock = 0x140102fc0;
    g_kernelStructs.KdpDataBlockEncoded = 0x14021144a;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version ['6', '1', '7601', '17514'], 64-bits */
static VOID Handler0x55ce0c(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7601', '17514'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x55ce0c;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f68b0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14005fd10 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCid = 0x3b0;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;

    Command.Structs.EProcessVadRootOffset = 0x448;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x21c0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140245e90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140227b90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x420;

    g_kernelStructs.ObpCreateHandle = 0x140378d40 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14008d620 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140377c90 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14006d4d0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x140398b2c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1403999e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x140397ad4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140397580 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140168460; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401f10a0;
    g_kernelStructs.KdCopyDataBlock = 0x140108c00;
    g_kernelStructs.KdpDataBlockEncoded = 0x1402194b2;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['6', '1', '7600', '16385'], 32-bits */
static VOID Handler0x3c9503(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7600', '16385'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c9503;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bb4df; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4bb3c1 - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*)(0x529c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x20 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCid = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x548810 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x540e98 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x62268d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x4857dd - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x64be0f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b3821 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x67fc41 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x67eed7 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x67bcdc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x67a25d - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4dd2d3; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x528be8;
    g_kernelStructs.KdCopyDataBlock = 0x4db45e;
    g_kernelStructs.KdpDataBlockEncoded = 0x536dd6;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['6', '1', '7601', '17514'], 32-bits */
static VOID Handler0x3c05d5(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7601', '17514'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c05d5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5731fc; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48656e - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*)(0x522c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x20 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCid = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x5405b0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x5396d8 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x612bf0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ec98 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60ae43 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d311 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e265 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x63794e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a2c4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6375e8 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d29eb; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x521c28;
    g_kernelStructs.KdCopyDataBlock = 0x4d0c6e;
    g_kernelStructs.KdpDataBlockEncoded = 0x52f616;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['5', '1', '2600', '5512'], 32-bits */
static VOID Handler0x2247c2(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['5', '1', '2600', '5512'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x2247c2;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4eb33f; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = 0;
    pKpcr = (KPCR*)0xffdff000;
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x120 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x168;
    Command.Structs.EThreadStackLimitOffset = 0x1c;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x1ec;

    Command.Structs.EProcessUniqueIdOffset = 0x84;
    Command.Structs.EProcessCommitChargeOffset = 0xa8;
    Command.Structs.EProcessVirtualSizeOffset = 0xb0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xac;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1ec;

    Command.Structs.EProcessVadRootOffset = 0x11c;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x868;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x4841c0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x48a358 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x48ded6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x411e70 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x491fc3 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4928ed - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x49acb1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x49cb61 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x49c6e6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x49c5ad - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x45bcaa; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x475de0;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_X86_)

/* Version ['6', '1', '7601', '17514'], 32-bits */
static VOID Handler0x3c88ac(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '1', '7601', '17514'] (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c88ac;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bae87; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba35a - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*)(0x52bc00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;    Command.Structs.EThreadSegmentOffset = 0x20 + 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCid = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x54a850 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x542f18 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x624980 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48e315 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62ba62 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4ba4db - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x644403 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x648394 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x66663a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x64802e - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4df4e7; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x52ac28;
    g_kernelStructs.KdCopyDataBlock = 0x4c9ab2;
    g_kernelStructs.KdpDataBlockEncoded = 0x538e56;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version ['6', '3', '9600', '17031'], 64-bits */
static VOID Handler0x71fad2(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    LOG("Registering data structures for version ['6', '3', '9600', '17031'] (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x71fad2;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404c16a8; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1403d0398 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x620;

    Command.Structs.EProcessUniqueIdOffset = 0x2e0;
    Command.Structs.EProcessCommitChargeOffset = 0x4d0;
    Command.Structs.EProcessVirtualSizeOffset = 0x328;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x320;
    Command.Structs.EProcessCommitChargePeakOffset = 0x6c8;

    Command.Structs.EProcessVadRootOffset = 0x5d8;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2dd0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x1402ca2d0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x1402b00a0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2e8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x470;
    g_kernelStructs.EThreadThreadListEntry = 0x688;

    g_kernelStructs.ObpCreateHandle = 0x1403f4d60 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140067220 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1403fd1c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14006d6c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14044bbc4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1404811e8 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1403c7b2c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x1403c7bd0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1401dcaac; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x140297a20;
    g_kernelStructs.KdCopyDataBlock = 0x1401d96d8;
    g_kernelStructs.KdpDataBlockEncoded = 0x1402a31c1;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}

#endif

#if defined(_AMD64_)

/* Version (10, 0, 15063, 0), 64-bits */
static VOID Handler0x7f010a(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (10, 0, 15063, 0) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x7f010a;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1405c1a20; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1404ba598 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*)__readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR)pKpcr;
    Command.Structs.KPRCB = (UINT_PTR)pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;    Command.Structs.EThreadSegmentOffset = 0x180 + 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCid = 0x638;

    Command.Structs.EProcessUniqueIdOffset = 0x2e0;
    Command.Structs.EProcessCommitChargeOffset = 0x4f0;
    Command.Structs.EProcessVirtualSizeOffset = 0x338;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x330;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4f8;

    Command.Structs.EProcessVadRootOffset = 0x628;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2e50;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x14034c5a0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140346000 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2e8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x488;
    g_kernelStructs.EThreadThreadListEntry = 0x6a0;

    g_kernelStructs.ObpCreateHandle = 0x14046b9a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14006dc80 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14047dd70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14047d3e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14047ef30 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x14047a7a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x140532a38 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14047b1d0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1401fbeb0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1403384f0;
    g_kernelStructs.KdCopyDataBlock = 0x1401f85cc;
    g_kernelStructs.KdpDataBlockEncoded = 0x14036b470;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x100);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif
