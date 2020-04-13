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
#include <intrin.h>
#include <s2e/s2e.h>
#include "winmonitor.h"
#include "kernel_structs.h"
#include "log.h"

#pragma warning(push)
#pragma warning(disable: 26451) // Arithmetic overflow

static REGISTER_KERNEL_STRUCTS Handler0x2247c2; /* (5, 1, 2600, 5512) - 32 - en_windows_xp_professional_with_service_pack_3_x86_cd_x14-80428_0c89243c7c3ee199b96fcc16990e0679_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x21a293; /* (5, 1, 2600, 5512) - 32 - en_windows_xp_professional_with_service_pack_3_x86_cd_x14-80428_40f8880122a030a7e9e1fedea833b33d_ntkrnlmp.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x1f77ce; /* (5, 1, 2600, 6748) - 32 - winxp-updates-x86-enu_2fdaa0aef7890bfa90bffefacbebe5b2_ntkrpamp.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x21b173; /* (5, 1, 2600, 6748) - 32 - winxp-updates-x86-enu_5c814a2794f27c25606c00740c40bfda_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x20df8e; /* (5, 1, 2600, 6748) - 32 - winxp-updates-x86-enu_6b5fbfe6e6f8804aa5f017d8f9548d80_ntkrnlmp.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x2055a8; /* (5, 1, 2600, 6748) - 32 - winxp-updates-x86-enu_feffd5228da5bbc12fb5f8f8b784179b_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3bdf03; /* (6, 1, 7600, 16988) - 32 - Windows6.1-KB2676562-x64_678ad0f9db55f9127851cd631456f483_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x54df57; /* (6, 1, 7600, 16988) - 64 - Windows6.1-KB2676562-x64_9579f84c40b3be205c9fd4ccdd99b6b7_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d1875; /* (6, 1, 7600, 16988) - 32 - Windows6.1-KB2676562-x64_9d19079820928d72a5708a668b5b62ae_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x5458e9; /* (6, 1, 7600, 21179) - 64 - Windows6.1-KB2676562-x64_5e6017e5814b3bc366a5a7a88538d0fc_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cac0a; /* (6, 1, 7600, 21179) - 32 - Windows6.1-KB2676562-x64_c6d1d128de4148e35b6c04b6892eb71a_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3be772; /* (6, 1, 7600, 21179) - 32 - Windows6.1-KB2676562-x64_d909eafa618bc9db2615303da3d9c830_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c88ac; /* (6, 1, 7601, 17514) - 32 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_144bd78c6103c8616de047b3532142db_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c05d5; /* (6, 1, 7601, 17514) - 32 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_2088d9994332583edb3c561de31ea5ad_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x55ce0c; /* (6, 1, 7601, 17514) - 64 - en_windows_7_enterprise_with_sp1_x64_dvd_u_677651_c6cec3e6cc9842b73501c70aa64c00fe_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x55a167; /* (6, 1, 7601, 17803) - 64 - Windows6.1-KB2676562-x64_03b5c6dba5a770ceefd1615e380c6bc3_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c0b67; /* (6, 1, 7601, 17803) - 32 - Windows6.1-KB2676562-x64_28f44480e411c3ddf04b63f6560e6ef4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cdcdc; /* (6, 1, 7601, 17803) - 32 - Windows6.1-KB2676562-x64_8f6d5704d7522aab8b4b82c0d35d9184_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d85d9; /* (6, 1, 7601, 18717) - 32 - Windows6.1-KB3004375-v3-x64_62c93e47a424a8ec79f3cf1719a2dcc6_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c8490; /* (6, 1, 7601, 18717) - 32 - Windows6.1-KB3004375-v3-x64_6d227897a458da8a9518dacdc88f1947_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x54c685; /* (6, 1, 7601, 18717) - 64 - Windows6.1-KB3004375-v3-x64_9819614ca9efb5a96493b379170b9d89_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cbb94; /* (6, 1, 7601, 18741) - 32 - Windows6.1-KB3033929-x64_2cfe69a0a8afda8db9a773d728000bb7_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cdec5; /* (6, 1, 7601, 18741) - 32 - Windows6.1-KB3033929-x64_6c2d4dc5d2e271f4ae4016fd4587b0b2_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x556afe; /* (6, 1, 7601, 18741) - 64 - Windows6.1-KB3033929-x64_fda5f186596288f0b9ece9dc7a5aa868_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cb323; /* (6, 1, 7601, 21955) - 32 - Windows6.1-KB2676562-x64_2e02a17e8965ad671e4987e503ad38b1_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x55d5dd; /* (6, 1, 7601, 21955) - 64 - Windows6.1-KB2676562-x64_708a4c721cee6b3845b5a54477d873cf_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d12ba; /* (6, 1, 7601, 21955) - 32 - Windows6.1-KB2676562-x64_93358348d0b79812caaa83a1377e4449_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x5512f5; /* (6, 1, 7601, 22923) - 64 - Windows6.1-KB3004375-v3-x64_12a78796fff4d5b8b15a2bc4b13650a4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d9d62; /* (6, 1, 7601, 22923) - 32 - Windows6.1-KB3004375-v3-x64_4997b61d205698d53420b877b8f76622_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c0103; /* (6, 1, 7601, 22923) - 32 - Windows6.1-KB3004375-v3-x64_bfca109d2f65a57389e03d63b0f86ee3_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cca4b; /* (6, 1, 7601, 22948) - 32 - Windows6.1-KB3033929-x64_ac9a49269b41ca6d814912ce7a2475e6_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cb498; /* (6, 1, 7601, 22948) - 32 - Windows6.1-KB3033929-x64_b6258de1ba2eb5f718b65d206d2912ce_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x5546f7; /* (6, 1, 7601, 22948) - 64 - Windows6.1-KB3033929-x64_f2b78d0219aa7d84c98e833c17937ddb_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x54beb6; /* (6, 1, 7601, 23403) - 64 - Windows6.1-KB3125574-v4-x64_2fc0d7944d4de0570a620a096980d798_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3cbe00; /* (6, 1, 7601, 23403) - 32 - Windows6.1-KB3125574-v4-x64_b3015aadb71f044d61c00bfa9776cdc4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d1fa6; /* (6, 1, 7601, 23403) - 32 - Windows6.1-KB3125574-v4-x64_fd672bc0422b5c797699a4dbedbdf075_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3df6b3; /* (6, 1, 7601, 23539) - 32 - Windows6.1-KB3172605-x64_6c776db52210002932f3c97c29fde894_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x54fc3a; /* (6, 1, 7601, 23539) - 64 - Windows6.1-KB3172605-x64_72d9fc1995b11d65fdaacf23c9607e85_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3c4618; /* (6, 1, 7601, 23539) - 32 - Windows6.1-KB3172605-x64_c7f9a2fbb73d75191fbf88acb2563765_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3ccf6e; /* (6, 1, 7601, 24384) - 32 - Windows6.1-KB4474419-v3-x64_064f8f992f157ceeb83d4ff48f88b9f9_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x54ffbe; /* (6, 1, 7601, 24384) - 64 - Windows6.1-KB4474419-v3-x64_aecff6fa02f533d525a7322c0c4fc3de_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3e16a6; /* (6, 1, 7601, 24384) - 32 - Windows6.1-KB4474419-v3-x64_ddb234708ae27e57906d36f18180678c_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3d72d7; /* (6, 1, 7601, 24545) - 32 - Windows6.1-KB4534310-x64_01cb6f291cc558576cdc94831e3a3439_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x3e5004; /* (6, 1, 7601, 24545) - 32 - Windows6.1-KB4534310-x64_4c182dcab1698bb8d71652d14eb30684_ntkrnlpa.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x551102; /* (6, 1, 7601, 24545) - 64 - Windows6.1-KB4534310-x64_cc4ab0c7ccd42ab51ba54499dcd9b3e4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x71a4f4; /* (6, 3, 9600, 16404) - 64 - en_windows_8_1_enterprise_x64_dvd_2971902_175783706eef1ca1d2be6c4f10bfe3b4_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x7f010a; /* (10, 0, 15063, 0) - 64 - en_windows_10_enterprise_version_1703_updated_march_2017_x64_dvd_10189290_335ee604bc5976ee83b38f3dddfed723_ntoskrnl.pdb */
static REGISTER_KERNEL_STRUCTS Handler0x97cabe; /* (10, 0, 18362, 418) - 64 - Win10_1909_EnglishInternational_x64_a45aaeef8e2fc6f0be3f91bae7764fcb_ntoskrnl.pdb */

REGISTER_KERNEL_STRUCTS_HANDLERS g_KernelStructHandlers [] = {
        #if defined(_X86_)
        { 0x2247c2, 0x400000, &Handler0x2247c2 }, /* (5, 1, 2600, 5512) - 32*/
    #endif
        #if defined(_X86_)
        { 0x21a293, 0x400000, &Handler0x21a293 }, /* (5, 1, 2600, 5512) - 32*/
    #endif
        #if defined(_X86_)
        { 0x1f77ce, 0x400000, &Handler0x1f77ce }, /* (5, 1, 2600, 6748) - 32*/
    #endif
        #if defined(_X86_)
        { 0x21b173, 0x400000, &Handler0x21b173 }, /* (5, 1, 2600, 6748) - 32*/
    #endif
        #if defined(_X86_)
        { 0x20df8e, 0x400000, &Handler0x20df8e }, /* (5, 1, 2600, 6748) - 32*/
    #endif
        #if defined(_X86_)
        { 0x2055a8, 0x400000, &Handler0x2055a8 }, /* (5, 1, 2600, 6748) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3bdf03, 0x400000, &Handler0x3bdf03 }, /* (6, 1, 7600, 16988) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x54df57, 0x140000000, &Handler0x54df57 }, /* (6, 1, 7600, 16988) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3d1875, 0x400000, &Handler0x3d1875 }, /* (6, 1, 7600, 16988) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x5458e9, 0x140000000, &Handler0x5458e9 }, /* (6, 1, 7600, 21179) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cac0a, 0x400000, &Handler0x3cac0a }, /* (6, 1, 7600, 21179) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3be772, 0x400000, &Handler0x3be772 }, /* (6, 1, 7600, 21179) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c88ac, 0x400000, &Handler0x3c88ac }, /* (6, 1, 7601, 17514) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c05d5, 0x400000, &Handler0x3c05d5 }, /* (6, 1, 7601, 17514) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x55ce0c, 0x140000000, &Handler0x55ce0c }, /* (6, 1, 7601, 17514) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x55a167, 0x140000000, &Handler0x55a167 }, /* (6, 1, 7601, 17803) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3c0b67, 0x400000, &Handler0x3c0b67 }, /* (6, 1, 7601, 17803) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cdcdc, 0x400000, &Handler0x3cdcdc }, /* (6, 1, 7601, 17803) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3d85d9, 0x400000, &Handler0x3d85d9 }, /* (6, 1, 7601, 18717) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c8490, 0x400000, &Handler0x3c8490 }, /* (6, 1, 7601, 18717) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x54c685, 0x140000000, &Handler0x54c685 }, /* (6, 1, 7601, 18717) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cbb94, 0x400000, &Handler0x3cbb94 }, /* (6, 1, 7601, 18741) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cdec5, 0x400000, &Handler0x3cdec5 }, /* (6, 1, 7601, 18741) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x556afe, 0x140000000, &Handler0x556afe }, /* (6, 1, 7601, 18741) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cb323, 0x400000, &Handler0x3cb323 }, /* (6, 1, 7601, 21955) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x55d5dd, 0x140000000, &Handler0x55d5dd }, /* (6, 1, 7601, 21955) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3d12ba, 0x400000, &Handler0x3d12ba }, /* (6, 1, 7601, 21955) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x5512f5, 0x140000000, &Handler0x5512f5 }, /* (6, 1, 7601, 22923) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3d9d62, 0x400000, &Handler0x3d9d62 }, /* (6, 1, 7601, 22923) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3c0103, 0x400000, &Handler0x3c0103 }, /* (6, 1, 7601, 22923) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cca4b, 0x400000, &Handler0x3cca4b }, /* (6, 1, 7601, 22948) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3cb498, 0x400000, &Handler0x3cb498 }, /* (6, 1, 7601, 22948) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x5546f7, 0x140000000, &Handler0x5546f7 }, /* (6, 1, 7601, 22948) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x54beb6, 0x140000000, &Handler0x54beb6 }, /* (6, 1, 7601, 23403) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3cbe00, 0x400000, &Handler0x3cbe00 }, /* (6, 1, 7601, 23403) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3d1fa6, 0x400000, &Handler0x3d1fa6 }, /* (6, 1, 7601, 23403) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3df6b3, 0x400000, &Handler0x3df6b3 }, /* (6, 1, 7601, 23539) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x54fc3a, 0x140000000, &Handler0x54fc3a }, /* (6, 1, 7601, 23539) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3c4618, 0x400000, &Handler0x3c4618 }, /* (6, 1, 7601, 23539) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3ccf6e, 0x400000, &Handler0x3ccf6e }, /* (6, 1, 7601, 24384) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x54ffbe, 0x140000000, &Handler0x54ffbe }, /* (6, 1, 7601, 24384) - 64*/
    #endif
        #if defined(_X86_)
        { 0x3e16a6, 0x400000, &Handler0x3e16a6 }, /* (6, 1, 7601, 24384) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3d72d7, 0x400000, &Handler0x3d72d7 }, /* (6, 1, 7601, 24545) - 32*/
    #endif
        #if defined(_X86_)
        { 0x3e5004, 0x400000, &Handler0x3e5004 }, /* (6, 1, 7601, 24545) - 32*/
    #endif
        #if defined(_AMD64_)
        { 0x551102, 0x140000000, &Handler0x551102 }, /* (6, 1, 7601, 24545) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x71a4f4, 0x140000000, &Handler0x71a4f4 }, /* (6, 3, 9600, 16404) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x7f010a, 0x140000000, &Handler0x7f010a }, /* (10, 0, 15063, 0) - 64*/
    #endif
        #if defined(_AMD64_)
        { 0x97cabe, 0x140000000, &Handler0x97cabe }, /* (10, 0, 18362, 418) - 64*/
    #endif
};


#if defined(_X86_)

/* Version (5, 1, 2600, 5512), 32-bits */
static VOID Handler0x2247c2(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
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
    KPCR *pKpcr = NULL;
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

/* Version (5, 1, 2600, 6748), 32-bits */
static VOID Handler0x1f77ce(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 6748) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x1f77ce;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4ac666; //IopDeleteDriver;
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x486720 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x48c8b8 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x4e6528 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x448ad8 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x4d1aee - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4dbfe6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x4e1452 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4db06e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4dbe7c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4dbcb6 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4224e0; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x4762e0;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (5, 1, 2600, 6748), 32-bits */
static VOID Handler0x21b173(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 6748) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x21b173;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4f2217; //IopDeleteDriver;
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x484340 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x48a4d8 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x48e056 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x411dc0 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x492302 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x492c2d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x49df70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4a5b31 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4a56b6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4a557d - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x45bcfa; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x475f60;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (5, 1, 2600, 6748), 32-bits */
static VOID Handler0x20df8e(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 6748) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x20df8e;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4d6fb6; //IopDeleteDriver;
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
    g_kernelStructs.MmAccessFault = 0x411c99 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x499da7 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x49a2a1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x4a8587 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4a3c39 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4a37c1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4a3688 - KernelNativeBase + KernelLoadBase;
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

/* Version (5, 1, 2600, 6748), 32-bits */
static VOID Handler0x2055a8(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (5, 1, 2600, 6748) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x2055a8;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x4a1c5c; //IopDeleteDriver;
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x47d1c0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x483358 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x88;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x190;
    g_kernelStructs.EThreadThreadListEntry = 0x22c;

    g_kernelStructs.ObpCreateHandle = 0x4dbf3c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x44545c - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x4c7006 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4d1660 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x4d6c78 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x4d06e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x4d14f6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x4d1330 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x42123c; //KeBugCheck2
    Command.Structs.KdVersionBlock = *(UINT_PTR*)(UINT_PTR)(Command.Structs.KPCR + 0x34);
    Command.Structs.KdDebuggerDataBlock = 0x46ece0;
    g_kernelStructs.KdCopyDataBlock = 0x0;
    g_kernelStructs.KdpDataBlockEncoded = 0x0;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x1c);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7600, 16988), 32-bits */
static VOID Handler0x3bdf03(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 16988) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3bdf03;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x572238; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x485c75 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x53f570 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x538658 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x61193c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45eac7 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x609bc3 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47cc29 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63d0bd - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x6367a6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65904f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x63643f - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d1a57; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x520c28;
    g_kernelStructs.KdCopyDataBlock = 0x4cfcda;
    g_kernelStructs.KdpDataBlockEncoded = 0x52e596;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7600, 16988), 64-bits */
static VOID Handler0x54df57(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 16988) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54df57;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404e8ab0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14004f09c - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x14023ce70 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x14021eb30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x420;

    g_kernelStructs.ObpCreateHandle = 0x140362d50 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140089b30 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036c220 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400b0f30 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1403868e4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140383b70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14038316c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140382c10 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140167120; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401e80a0;
    g_kernelStructs.KdCopyDataBlock = 0x1401024d0;
    g_kernelStructs.KdpDataBlockEncoded = 0x14021044a;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7600, 16988), 32-bits */
static VOID Handler0x3d1875(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 16988) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d1875;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bbbc3; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4bb51c - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x548810 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x540e98 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x622afb - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48593d - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x64c43b - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b396d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x6802ef - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x67f585 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x67c38a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x67a90b - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4dd467; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x528c28;
    g_kernelStructs.KdCopyDataBlock = 0x4db5f2;
    g_kernelStructs.KdpDataBlockEncoded = 0x536dd6;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7600, 21179), 64-bits */
static VOID Handler0x5458e9(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 21179) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x5458e9;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404e09d0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x140043c50 - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140234eb0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140216b70 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x420;

    g_kernelStructs.ObpCreateHandle = 0x14035a400 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140080670 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140363bb0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x1400ae0e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14037f014 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x14037c280 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14037b874 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14037b440 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x14015f560; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401e00a0;
    g_kernelStructs.KdCopyDataBlock = 0x1400fb170;
    g_kernelStructs.KdpDataBlockEncoded = 0x14020848a;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7600, 21179), 32-bits */
static VOID Handler0x3cac0a(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 21179) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cac0a;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bd59b; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4bdde5 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x549890 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x541f18 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x62413b - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x488221 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x64db53 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b6274 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x681b07 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x680d9d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x67db16 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x67c098 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4dfb63; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x529c28;
    g_kernelStructs.KdCopyDataBlock = 0x4ddcf6;
    g_kernelStructs.KdpDataBlockEncoded = 0x537e56;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7600, 21179), 32-bits */
static VOID Handler0x3be772(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7600, 21179) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3be772;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573238; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x486552 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x5405f0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x5396d8 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x61310d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ecc8 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60b35f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d31d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e875 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x637f5e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a8fa - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x637bf8 - KernelNativeBase + KernelLoadBase;
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

/* Version (6, 1, 7601, 17514), 32-bits */
static VOID Handler0x3c88ac(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17514) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c88ac;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bae87; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba35a - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17514) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c05d5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5731fc; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48656e - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
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


#if defined(_AMD64_)

/* Version (6, 1, 7601, 17803), 64-bits */
static VOID Handler0x55a167(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17803) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x55a167;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f47b0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14005dc54 - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140244670 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140226370 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x140373450 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14008b410 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1403723a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14006b3d0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1403932bc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140394170 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x140392264 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140391d10 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1401677e0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401f00a0;
    g_kernelStructs.KdCopyDataBlock = 0x140107d10;
    g_kernelStructs.KdpDataBlockEncoded = 0x140218122;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 17803), 32-bits */
static VOID Handler0x3c0b67(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17803) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c0b67;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x572239; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48658c - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x540230 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x539358 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x611d19 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ecb8 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x609f65 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d32e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63d483 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x636b6d - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x659508 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x636807 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d29b3; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x521c28;
    g_kernelStructs.KdCopyDataBlock = 0x4d0c36;
    g_kernelStructs.KdpDataBlockEncoded = 0x52f39e;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 17803), 32-bits */
static VOID Handler0x3cdcdc(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 17803) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cdcdc;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6ba13b; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba2f9 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x5494d0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x541b98 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x623aa2 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48e2b9 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62abcc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4ba47a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x643581 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x647512 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x66585a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6471ac - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4df463; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x529c28;
    g_kernelStructs.KdCopyDataBlock = 0x4c9a4c;
    g_kernelStructs.KdpDataBlockEncoded = 0x537bde;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 18717), 32-bits */
static VOID Handler0x3d85d9(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18717) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d85d9;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bb9e5; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b97eb - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    g_kernelStructs.ObpCreateHandle = 0x624c40 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48d8a9 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62bd68 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b996c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x64478f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x64872f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x666afa - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6483c9 - KernelNativeBase + KernelLoadBase;
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


#if defined(_X86_)

/* Version (6, 1, 7601, 18717), 32-bits */
static VOID Handler0x3c8490(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18717) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c8490;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48655e - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    g_kernelStructs.ObpCreateHandle = 0x612eae - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ed60 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60b0ff - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d300 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e6d1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x637dbb - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a736 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x637a55 - KernelNativeBase + KernelLoadBase;
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


#if defined(_AMD64_)

/* Version (6, 1, 7601, 18717), 64-bits */
static VOID Handler0x54c685(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18717) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54c685;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f2ff0; //IopDeleteDriver;
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

/* Version (6, 1, 7601, 18741), 32-bits */
static VOID Handler0x3cbb94(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18741) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cbb94;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48655e - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 18741) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cdec5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bba05; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b97eb - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
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

/* Version (6, 1, 7601, 21955), 32-bits */
static VOID Handler0x3cb323(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 21955) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cb323;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x572239; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48646c - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x540230 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x539358 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x611ec9 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45eb98 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60a115 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d20e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63d647 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x636d30 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x6596f0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x6369ca - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d28db; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x521c38;
    g_kernelStructs.KdCopyDataBlock = 0x4d0b5e;
    g_kernelStructs.KdpDataBlockEncoded = 0x52f39e;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 21955), 64-bits */
static VOID Handler0x55d5dd(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 21955) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x55d5dd;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f4fc0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14005dbf4 - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140244670 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140226370 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x140373b70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14008b3f0 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140372ac0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14006b340 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1403939e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1403948a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x140392990 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x140392430 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140167900; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401f00c0;
    g_kernelStructs.KdCopyDataBlock = 0x140107dd0;
    g_kernelStructs.KdpDataBlockEncoded = 0x140218122;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 21955), 32-bits */
static VOID Handler0x3d12ba(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 21955) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d12ba;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6ba2d7; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba229 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x5494d0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x541b98 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x623c82 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48ded3 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62adac - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4ba3aa - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x643751 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x6476e2 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x665a2a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x64737c - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4df397; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x529c40;
    g_kernelStructs.KdCopyDataBlock = 0x4c997d;
    g_kernelStructs.KdpDataBlockEncoded = 0x537bde;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 22923), 64-bits */
static VOID Handler0x5512f5(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22923) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x5512f5;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f2490; //IopDeleteDriver;
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

    g_kernelStructs.ObpCreateHandle = 0x14036eb30 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140080100 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036ccf0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x140060160 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14038fff0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140391380 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14038fa54 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14038f500 - KernelNativeBase + KernelLoadBase;
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


#if defined(_X86_)

/* Version (6, 1, 7601, 22923), 32-bits */
static VOID Handler0x3d9d62(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22923) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d9d62;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bb88b; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b980b - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    g_kernelStructs.ObpCreateHandle = 0x624e50 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48dd39 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62bf78 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4b998c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x644b2b - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x648acd - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x666560 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x648767 - KernelNativeBase + KernelLoadBase;
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


#if defined(_X86_)

/* Version (6, 1, 7601, 22923), 32-bits */
static VOID Handler0x3c0103(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22923) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c0103;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48669e - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    g_kernelStructs.ObpCreateHandle = 0x612c2b - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45ee90 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60ae73 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47d440 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x63e3af - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x637a98 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65a5a6 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x637732 - KernelNativeBase + KernelLoadBase;
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
static VOID Handler0x3cca4b(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22948) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cca4b;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x573262; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48669e - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 22948) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cb498;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bb911; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4b980b - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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
    KPCR *pKpcr = NULL;
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

/* Version (6, 1, 7601, 23403), 64-bits */
static VOID Handler0x54beb6(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23403) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54beb6;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f33b0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14004ef4c - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140242730 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140224420 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x14036bd70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14007c630 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x140369f30 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14005ccb0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14038d3a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x14038e730 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14038ce00 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14038c8a0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140161930; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401ed110;
    g_kernelStructs.KdCopyDataBlock = 0x140104e90;
    g_kernelStructs.KdpDataBlockEncoded = 0x140205f7f;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 23403), 32-bits */
static VOID Handler0x3cbe00(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23403) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3cbe00;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x576267; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4871b4 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x543b90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53ccb0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x616275 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45f7c0 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60e48f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47dc8c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x641d5f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x63b0c5 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65e4bc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x63ad5f - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d364b; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x524c70;
    g_kernelStructs.KdCopyDataBlock = 0x4d18d0;
    g_kernelStructs.KdpDataBlockEncoded = 0x532457;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 23403), 32-bits */
static VOID Handler0x3d1fa6(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23403) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d1fa6;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6bfdc9; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba58f - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x54ce30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x5454f0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x628580 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48e849 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62f682 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4ba710 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x648427 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x64c3cb - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x669f20 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x64c065 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4e01eb; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x52cc78;
    g_kernelStructs.KdCopyDataBlock = 0x4ca71a;
    g_kernelStructs.KdpDataBlockEncoded = 0x53ac97;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 23539), 32-bits */
static VOID Handler0x3df6b3(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23539) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3df6b3;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6c003d; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4ba61f - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x54ce30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x5454f0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x628750 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48e8c1 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x62f852 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4ba7a0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x64865f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x64c603 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x66a160 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x64c29d - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4e02af; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x52cc78;
    g_kernelStructs.KdCopyDataBlock = 0x4ca7aa;
    g_kernelStructs.KdpDataBlockEncoded = 0x53ac97;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 23539), 64-bits */
static VOID Handler0x54fc3a(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23539) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54fc3a;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404f2590; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14004ef04 - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140242730 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140224420 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x14036df70 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14007c440 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x14036c130 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14005cc90 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x14038f590 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x140390920 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x14038eff4 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x14038eaa0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x140161ad0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401ed110;
    g_kernelStructs.KdCopyDataBlock = 0x140105020;
    g_kernelStructs.KdpDataBlockEncoded = 0x140205f7f;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 23539), 32-bits */
static VOID Handler0x3c4618(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 23539) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3c4618;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x576267; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x487254 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x543b90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53ccb0 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x61630a - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x45f860 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60e517 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x47dd2c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x641f79 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x63b2de - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65e6dc - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x63af78 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d36b7; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x524c70;
    g_kernelStructs.KdCopyDataBlock = 0x4d193c;
    g_kernelStructs.KdpDataBlockEncoded = 0x532457;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 24384), 32-bits */
static VOID Handler0x3ccf6e(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24384) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3ccf6e;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5773d6; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x489db8 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x544c10 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53dd30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x617776 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x4623a6 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60f965 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x48081e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x64350f - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x63c859 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65fca3 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x63c4f3 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d576f; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x529380;
    g_kernelStructs.KdCopyDataBlock = 0x4d396c;
    g_kernelStructs.KdpDataBlockEncoded = 0x5334db;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 24384), 64-bits */
static VOID Handler0x54ffbe(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24384) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x54ffbe;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404e33d0; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14002269c - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140239c90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x14021b940 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x1402f6580 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14016b240 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1404996e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14002e4c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1402e4180 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1402e62b0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1402dd00c - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x1402ec7c0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x14014eea0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401e2120;
    g_kernelStructs.KdCopyDataBlock = 0x1400db890;
    g_kernelStructs.KdpDataBlockEncoded = 0x1401ffd1b;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 24384), 32-bits */
static VOID Handler0x3e16a6(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24384) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3e16a6;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6c8eed; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4bc950 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x555730 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x54dd70 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x630e67 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48b249 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x637faf - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4bcad1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x650e93 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x654e99 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x672e14 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x654b33 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4e328b; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x538de8;
    g_kernelStructs.KdCopyDataBlock = 0x4ccef9;
    g_kernelStructs.KdpDataBlockEncoded = 0x54351b;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 24545), 32-bits */
static VOID Handler0x3d72d7(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24545) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3d72d7;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x5773f9; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x48a5b8 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x544c10 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x53dd30 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x617802 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x462ba6 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x60f9f1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x48101e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x643606 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x63c950 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x65fdfa - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x63c5ea - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4d5f4f; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x5295e8;
    g_kernelStructs.KdCopyDataBlock = 0x4d40f0;
    g_kernelStructs.KdpDataBlockEncoded = 0x5334db;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_X86_)

/* Version (6, 1, 7601, 24545), 32-bits */
static VOID Handler0x3e5004(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24545) (32-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x3e5004;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x6ca05f; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x4bcf20 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readfsdword(offsetof(KPCR, SelfPcr));
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x556730 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x54ed70 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0xb8;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x188;
    g_kernelStructs.EThreadThreadListEntry = 0x268;

    g_kernelStructs.ObpCreateHandle = 0x631eef - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x48b819 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x63904e - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x4bd0a1 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x651f59 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x655f71 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x673f44 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x655c0b - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x4e386b; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x539de8;
    g_kernelStructs.KdCopyDataBlock = 0x4cd4c9;
    g_kernelStructs.KdpDataBlockEncoded = 0x54451b;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x18);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 1, 7601, 24545), 64-bits */
static VOID Handler0x551102(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (6, 1, 7601, 24545) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x551102;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x1404e3b00; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x14001e5e4 - KernelNativeBase + KernelLoadBase);
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

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140239c90 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x14021b940 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x188;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x308;
    g_kernelStructs.EThreadThreadListEntry = 0x428;

    g_kernelStructs.ObpCreateHandle = 0x1402f9b20 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x14016b690 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1404992d0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14003ebd0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x1402ea130 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1402eb830 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1402de604 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x1402f53c0 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x14014f2f0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1401e2130;
    g_kernelStructs.KdCopyDataBlock = 0x1400dbd50;
    g_kernelStructs.KdpDataBlockEncoded = 0x1401ffd1b;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x40);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#if defined(_AMD64_)

/* Version (6, 3, 9600, 16404), 64-bits */
static VOID Handler0x71a4f4(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
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
    KPCR *pKpcr = NULL;
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


#if defined(_AMD64_)

/* Version (10, 0, 18362, 418), 64-bits */
static VOID Handler0x97cabe(UINT_PTR KernelLoadBase, UINT_PTR KernelNativeBase)
{
    KPCR *pKpcr = NULL;
    S2E_WINMON2_COMMAND Command;

    S2EMessage("Registering data structures for version (10, 0, 18362, 418) (64-bits)\n");

    MonitorInitCommon(&Command);
    Command.Structs.KernelChecksum = 0x97cabe;
    Command.Structs.KernelLoadBase = KernelLoadBase;
    Command.Structs.KernelNativeBase = KernelNativeBase;

    //Not supported by automatic generation
    //Command.Structs.LoadDriverPc = 000;
    Command.Structs.UnloadDriverPc = 0x14077e810; //IopDeleteDriver;
    Command.Structs.PerfLogImageUnload = (UINT_PTR)(0x1406cead8 - KernelNativeBase + KernelLoadBase);
    pKpcr = (KPCR*) __readmsr(IA32_GS_BASE);
    Command.Structs.KPCR = (UINT_PTR) pKpcr;
    Command.Structs.KPRCB = (UINT_PTR) pKpcr->CurrentPrcb;

    Command.Structs.EThreadSegment = R_GS;
    Command.Structs.EThreadSegmentOffset = 0x8;
    Command.Structs.EThreadStackBaseOffset = 0x38;
    Command.Structs.EThreadStackLimitOffset = 0x30;
    Command.Structs.EThreadProcessOffset = 0x220;
    Command.Structs.EThreadCidOffset = 0x648;

    Command.Structs.EProcessUniqueIdOffset = 0x2e8;
    Command.Structs.EProcessCommitChargeOffset = 0x4f0;
    Command.Structs.EProcessVirtualSizeOffset = 0x340;
    Command.Structs.EProcessPeakVirtualSizeOffset = 0x338;
    Command.Structs.EProcessCommitChargePeakOffset = 0x4f8;
    Command.Structs.EProcessExitStatusOffset = 0x654;

    Command.Structs.EProcessVadRootOffset = 0x658;

    Command.Structs.DPCStackBasePtr = Command.Structs.KPRCB + 0x2e50;
    Command.Structs.DPCStackSize = 24 * 1024;

    Command.Structs.PsLoadedModuleList = (UINT_PTR)(0x140448210 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.PsActiveProcessHead = (PLIST_ENTRY)(0x140438b40 - KernelNativeBase + KernelLoadBase);
    g_kernelStructs.EProcessActiveProcessLinkOffset = 0x2f0;
    g_kernelStructs.EProcessThreadListHeadOffset = 0x488;
    g_kernelStructs.EThreadThreadListEntry = 0x6b8;

    g_kernelStructs.ObpCreateHandle = 0x1405e9b80 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MmAccessFault = 0x140072b90 - KernelNativeBase + KernelLoadBase;

    g_kernelStructs.NtAllocateVirtualMemory = 0x1406505c0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtFreeVirtualMemory = 0x14065aec0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtProtectVirtualMemory = 0x140657cc0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtMapViewOfSection = 0x1405d7860 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.NtUnmapViewOfSection = 0x1405c71e0 - KernelNativeBase + KernelLoadBase;
    g_kernelStructs.MiUnmapViewOfSection = 0x1405c7530 - KernelNativeBase + KernelLoadBase;
    //g_kernelStructs.NtUnmapViewOfSectionEx =  - KernelNativeBase + KernelLoadBase;

    /* Crash dump functionality */
    Command.Structs.KeBugCheckEx = 0x1402a81c0; //KeBugCheck2
    Command.Structs.KdDebuggerDataBlock = 0x1404265e0;
    g_kernelStructs.KdCopyDataBlock = 0x1402a2214;
    g_kernelStructs.KdpDataBlockEncoded = 0x14046a3f8;

    g_kernelStructs.PRCBProcessorStateOffset = (PVOID)(UINT_PTR)(Command.Structs.KPRCB + 0x100);

    g_WinmonKernelStructs = Command.Structs;

    S2EInvokePlugin("WindowsMonitor", &Command, sizeof(Command));
}
#endif


#pragma warning(pop)