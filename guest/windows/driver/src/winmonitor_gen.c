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

/* Automatically generated code. Do not edit. */
// Resharper disable all

#include <ntddk.h>
#include <ntimage.h>
#include <Aux_klib.h>
#include <s2e/s2e.h>
#include "winmonitor.h"
#include "kernel_structs.h"
#include "log.h"

#pragma warning(push)
#pragma warning(disable: 26451) // Arithmetic overflow

static REGISTER_KERNEL_STRUCTS Handler0x2247c2; /* (5, 1, 2600, 5512) - 32 - en_windows_xp_professional_with_service_pack_3_x86_cd_x14-80428_0c89243c7c3ee199b96fcc16990e0679_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x21a293; /* (5, 1, 2600, 5512) - 32 - en_windows_xp_professional_with_service_pack_3_x86_cd_x14-80428_40f8880122a030a7e9e1fedea833b33d_ntkrnlmp.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c88ac; /* (6, 1, 7601, 17514) - 32 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_144bd78c6103c8616de047b3532142db_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c05d5; /* (6, 1, 7601, 17514) - 32 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_2088d9994332583edb3c561de31ea5ad_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x55ce0c; /* (6, 1, 7601, 17514) - 64 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_c6cec3e6cc9842b73501c70aa64c00fe_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cbb94; /* (6, 1, 7601, 18741) - 32 - Windows6.1-KB3033929-x64_2cfe69a0a8afda8db9a773d728000bb7_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cdec5; /* (6, 1, 7601, 18741) - 32 - Windows6.1-KB3033929-x64_6c2d4dc5d2e271f4ae4016fd4587b0b2_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x556afe; /* (6, 1, 7601, 18741) - 64 - Windows6.1-KB3033929-x64_fda5f186596288f0b9ece9dc7a5aa868_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cca4b; /* (6, 1, 7601, 22948) - 32 - Windows6.1-KB3033929-x64_ac9a49269b41ca6d814912ce7a2475e6_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cb498; /* (6, 1, 7601, 22948) - 32 - Windows6.1-KB3033929-x64_b6258de1ba2eb5f718b65d206d2912ce_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x5546f7; /* (6, 1, 7601, 22948) - 64 - Windows6.1-KB3033929-x64_f2b78d0219aa7d84c98e833c17937ddb_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x71a4f4; /* (6, 3, 9600, 16404) - 64 - en_windows_8_1_enterprise_x64_dvd_2971902_175783706eef1ca1d2be6c4f10bfe3b4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x7f010a; /* (10, 0, 15063, 0) - 64 - en_windows_10_enterprise_version_1703_updated_march_2017_x64_dvd_10189290_335ee604bc5976ee83b38f3dddfed723_ntoskrnl.pdb */

REGISTER_KERNEL_STRUCTS_HANDLERS g_KernelStructHandlers [] = {
        #if defined(_X86_)
        { 0x2247c2, &Handler0x2247c2 }, /* (5, 1, 2600, 5512) - 32*/
    #endif
        #if defined(_X86_)
        { 0x21a293, &Handler0x21a293 }, /* (5, 1, 2600, 5512) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c88ac, &Handler0x3c88ac }, /* (6, 1, 7601, 17514) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c05d5, &Handler0x3c05d5 }, /* (6, 1, 7601, 17514) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x55ce0c, &Handler0x55ce0c }, /* (6, 1, 7601, 17514) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cbb94, &Handler0x3cbb94 }, /* (6, 1, 7601, 18741) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cdec5, &Handler0x3cdec5 }, /* (6, 1, 7601, 18741) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x556afe, &Handler0x556afe }, /* (6, 1, 7601, 18741) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cca4b, &Handler0x3cca4b }, /* (6, 1, 7601, 22948) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cb498, &Handler0x3cb498 }, /* (6, 1, 7601, 22948) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x5546f7, &Handler0x5546f7 }, /* (6, 1, 7601, 22948) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x71a4f4, &Handler0x71a4f4 }, /* (6, 3, 9600, 16404) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x7f010a, &Handler0x7f010a }, /* (10, 0, 15063, 0) - 64*/
    #endif
};


#if defined(_X86_)

/* Version (5, 1, 2600, 5512), 32-bits */
static VOID Handler0x2247c2(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 5512) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x2247c2;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4eb33f; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = 0;
    pKpcr = (KPCR*) 0xffdff000;
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x168;
    Command.Structs.EThreadStackLimitOffset = 0x1c;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCidOffset = 0x1ec;

    Command.Structs.EProcessUniqueIdOffset = 0x84;
    Command.Structs.EProcessCommitChargeOffset = 0xa8;
    Command.Structs.EProcessVirtualSizeOffset = 0xb0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xac;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1ec;
    Command.Structs.EProcessExitStatusOffset = 0x24c;

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

/* Version (5, 1, 2600, 5512), 32-bits */
static VOID Handler0x21a293(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 5512) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x21a293;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4d067e; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = 0;
    pKpcr = (KPCR*) 0xffdff000;
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x168;
    Command.Structs.EThreadStackLimitOffset = 0x1c;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCidOffset = 0x1ec;

    Command.Structs.EProcessUniqueIdOffset = 0x84;
    Command.Structs.EProcessCommitChargeOffset = 0xa8;
    Command.Structs.EProcessVirtualSizeOffset = 0xb0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xac;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1ec;
    Command.Structs.EProcessExitStatusOffset = 0x24c;

    Command.Structs.EProcessVadRootOffset = 0x11c;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x868;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x48c4c0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x492658 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x496238 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x411969 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x499d45 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x49a3df - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x4aa891 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4a7371 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4a6ef9 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4a6dc0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x45faea; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x47c2e0;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 17514), 32-bits */
static VOID Handler0x3c88ac(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17514) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c88ac;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bae87; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba35a - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x52bc00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

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


#if defined(_X86_)

/* Version (6, 1, 7601, 17514), 32-bits */
static VOID Handler0x3c05d5(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17514) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c05d5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5731fc; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48656e - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x522c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

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


#if defined(_AMD64_)

/* Version (6, 1, 7601, 17514), 64-bits */
static VOID Handler0x55ce0c(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17514) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x55ce0c;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f68b0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14005fd10 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCidOffset = 0x3b0;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;
    Command.Structs.EProcessExitStatusOffset = 0x444;

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

/* Version (6, 1, 7601, 18741), 32-bits */
static VOID Handler0x3cbb94(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18741) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cbb94;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48655e - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x523c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x541310 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53a448 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x612f1e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ed60 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60b16f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d300 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e741 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x637e2b - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a7a6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x637ac5 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d28ff; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x522c28;
    g_kernelStructs.KdCopyDataBlock = 0x4d0b84;
    g_kernelStructs.KdpDataBlockEncoded = 0x530353;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 18741), 32-bits */
static VOID Handler0x3cdec5(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18741) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cdec5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bba05; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b97eb - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x52bc00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x54a5b0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x542c88 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x624cb0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48d8a9 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62bdd8 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b996c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x6447ff - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x64879f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x666b6a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x648439 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4df39f; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x52ac30;
    g_kernelStructs.KdCopyDataBlock = 0x4c98ef;
    g_kernelStructs.KdpDataBlockEncoded = 0x538b93;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 18741), 64-bits */
static VOID Handler0x556afe(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18741) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x556afe;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f3080; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14005467c - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCidOffset = 0x3b8;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;
    Command.Structs.EProcessExitStatusOffset = 0x444;

    Command.Structs.EProcessVadRootOffset = 0x448;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x21c0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140244890 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140226590 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x140370700 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140081d60 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036e8c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x140061db0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1403921b0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140393580 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x140391154 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140390c00 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140167390; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401f00a0;
    g_kernelStructs.KdCopyDataBlock = 0x1401078f0;
    g_kernelStructs.KdpDataBlockEncoded = 0x14020c0e3;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 22948), 32-bits */
static VOID Handler0x3cca4b(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22948) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cca4b;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48669e - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x523c00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x541310 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53a448 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x612cab - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ee90 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60aef3 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d440 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e42f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x637b18 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a626 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6377b2 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d2a53; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x522c40;
    g_kernelStructs.KdCopyDataBlock = 0x4d0cd8;
    g_kernelStructs.KdpDataBlockEncoded = 0x530353;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 22948), 32-bits */
static VOID Handler0x3cb498(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22948) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cb498;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bb911; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b980b - KernelNativeBase + KernelLoadBase);        pKpcr = (KPCR*) (0x52bc00 - KernelNativeBase + KernelLoadBase);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->Prcb;

    Command.Structs.EThreadSegment = R_FS;
    Command.Structs.EThreadSegmentOffset = 0x4;
    Command.Structs.EThreadStackBaseOffset = 0x190;
    Command.Structs.EThreadStackLimitOffset = 0x2c;
    Command.Structs.EThreadProcessOffset = 0x150;
    Command.Structs.EThreadCidOffset = 0x22c;

    Command.Structs.EProcessUniqueIdOffset = 0xb4;
    Command.Structs.EProcessCommitChargeOffset = 0xd0;
    Command.Structs.EProcessVirtualSizeOffset = 0xe0;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0xdc;
    Command.Structs.EProcessCommitChargePeakOffset = 0x1e4;
    Command.Structs.EProcessExitStatusOffset = 0x274;

    Command.Structs.EProcessVadRootOffset = 0x278;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x1908;
    Command.Structs.DPCStackSize = 0x3000;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x54a5b0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x542c88 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x624ed0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48dd39 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62bff8 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b998c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x644bab - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x648b4d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x6665e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6487e7 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4df3b3; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x52ac40;
    g_kernelStructs.KdCopyDataBlock = 0x4c9910;
    g_kernelStructs.KdpDataBlockEncoded = 0x538b93;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 22948), 64-bits */
static VOID Handler0x5546f7(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22948) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x5546f7;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f2520; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1400526d0 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x278;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x210;
    Command.Structs.EThreadCidOffset = 0x3b8;

    Command.Structs.EProcessUniqueIdOffset = 0x180;
    Command.Structs.EProcessCommitChargeOffset = 0x1b8;
    Command.Structs.EProcessVirtualSizeOffset = 0x1d8;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x1d0;
    Command.Structs.EProcessCommitChargePeakOffset = 0x380;
    Command.Structs.EProcessExitStatusOffset = 0x444;

    Command.Structs.EProcessVadRootOffset = 0x448;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x21c0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140243890 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140225590 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x14036e7b0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140080100 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036c970 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x140060160 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14038fc70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140391000 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14038f6d4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14038f180 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140166ec0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401ef0d0;
    g_kernelStructs.KdCopyDataBlock = 0x140107490;
    g_kernelStructs.KdpDataBlockEncoded = 0x14020b0e3;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 3, 9600, 16404), 64-bits */
static VOID Handler0x71a4f4(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 3, 9600, 16404) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x71a4f4;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404d1534; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1403a272c - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCidOffset = 0x620;

    Command.Structs.EProcessUniqueIdOffset = 0x2e0;
    Command.Structs.EProcessCommitChargeOffset = 0x4d8;
    Command.Structs.EProcessVirtualSizeOffset = 0x328;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x320;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4e0;
    Command.Structs.EProcessExitStatusOffset = 0x5d4;

    Command.Structs.EProcessVadRootOffset = 0x5d8;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2dd0;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x1402c4990 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x1402aa7a0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2e8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x470;
    g_kernelStructs.EThreadThreadListEntry = 0x688;

    g_kernelStructs.ObpCreateHandle = 0x1403c5350 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140060910 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1403d6120 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400684c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1403d9a78 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1403d8a10 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1404a76a8 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x1403d4f78 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1401d5100; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x140293a30;
    g_kernelStructs.KdCopyDataBlock = 0x1401d227c;
    g_kernelStructs.KdpDataBlockEncoded = 0x14029f0d1;

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
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCidOffset = 0x638;

    Command.Structs.EProcessUniqueIdOffset = 0x2e0;
    Command.Structs.EProcessCommitChargeOffset = 0x4f0;
    Command.Structs.EProcessVirtualSizeOffset = 0x338;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x330;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4f8;
    Command.Structs.EProcessExitStatusOffset = 0x624;

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


#pragma warning(pop)