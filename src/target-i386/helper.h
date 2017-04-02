/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include "def-helper.h"

#include <cpu/i386/helper.h>

/* NOTE: by putting 0 here we ignore possible invocation of vmexit.
         If we want to correctly simulate it, we should put 1 here! */
#if 0

#define _RM_EXCP (_M_CC | _M_ESP | _M_EAX)
#define _WM_EXCP (_M_CC | _M_ESP | _M_EAX)
#define _AM_EXCP 1

#else

#define _RM_EXCP (_M_CC)
#define _WM_EXCP (_M_CC)
#define _AM_EXCP 0

#endif

DEF_HELPER_FLAGS_1_M(cc_compute_all, TCG_CALL_PURE, i32, int, _M_CC, 0, 0)
DEF_HELPER_FLAGS_1_M(cc_compute_c, TCG_CALL_PURE, i32, int, _M_CC, 0, 0)

DEF_HELPER_0_M(lock, void, 0, 0, 0)
DEF_HELPER_0_M(unlock, void, 0, 0, 0)
DEF_HELPER_2_M(write_eflags, void, tl, i32, 0, _M_CC_SRC, 0)
DEF_HELPER_0_M(read_eflags, tl, _M_CC, 0, 0)
DEF_HELPER_1_M(divb_AL, void, tl, _M_EAX | _RM_EXCP, _M_EAX | _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(idivb_AL, void, tl, _M_EAX | _RM_EXCP, _M_EAX | _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(divw_AX, void, tl, _M_EAX | _M_EDX | _RM_EXCP, _M_EAX | _M_EDX | _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(idivw_AX, void, tl, _M_EAX | _M_EDX | _RM_EXCP, _M_EAX | _M_EDX | _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(divl_EAX, void, tl, _M_EAX | _M_EDX | _RM_EXCP, _M_EAX | _M_EDX | _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(idivl_EAX, void, tl, _M_EAX | _M_EDX | _RM_EXCP, _M_EAX | _M_EDX | _WM_EXCP, _AM_EXCP)
#ifdef TARGET_X86_64
DEF_HELPER_1(mulq_EAX_T0, void, tl)
DEF_HELPER_1(imulq_EAX_T0, void, tl)
DEF_HELPER_2(imulq_T0_T1, tl, tl, tl)
DEF_HELPER_1(divq_EAX, void, tl)
DEF_HELPER_1(idivq_EAX, void, tl)
#endif

DEF_HELPER_1_M(aam, void, int, _M_EAX, _M_EAX | _M_CC_DST, 0)
DEF_HELPER_1_M(aad, void, int, _M_EAX, _M_EAX | _M_CC_DST, 0)
DEF_HELPER_0_M(aaa, void, _M_EAX | _M_CC, _M_EAX | _M_CC_SRC, 0)
DEF_HELPER_0_M(aas, void, _M_EAX | _M_CC, _M_EAX | _M_CC_SRC, 0)
DEF_HELPER_0_M(daa, void, _M_EAX | _M_CC, _M_EAX | _M_CC_SRC, 0)
DEF_HELPER_0_M(das, void, _M_EAX | _M_CC, _M_EAX | _M_CC_SRC, 0)

/* NOTE: segment-related instructions access memory, but the value
         will be concretized anyway because it is stored in
         always-concrete part of the CPUState */
DEF_HELPER_1_M(lsl, tl, tl, _M_CC, _M_CC_SRC, 0)
DEF_HELPER_1_M(lar, tl, tl, _M_CC, _M_CC_SRC, 0)
DEF_HELPER_1_M(verr, void, tl, _M_CC, _M_CC_SRC, 0)
DEF_HELPER_1_M(verw, void, tl, _M_CC, _M_CC_SRC, 0)
DEF_HELPER_1_M(lldt, void, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(ltr, void, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_2_M(load_seg, void, int, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_3_M(ljmp_protected, void, int, tl, int, (uint64_t) -1, (uint64_t) -1, _AM_EXCP)
DEF_HELPER_4_M(lcall_real, void, int, tl, int, int, _M_ESP, _M_ESP, 0)
DEF_HELPER_4_M(lcall_protected, void, int, tl, int, int, (uint64_t) -1, (uint64_t) -1, _AM_EXCP)
DEF_HELPER_1_M(iret_real, void, int, _M_ESP, _M_ESP | _M_CC_SRC, 1)
DEF_HELPER_2_M(iret_protected, void, int, int, (uint64_t) -1, (uint64_t) -1, 1)
DEF_HELPER_2_M(lret_protected, void, int, int, (uint64_t) -1, (uint64_t) -1, 1)
DEF_HELPER_1_M(read_crN, tl, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_2_M(write_crN, void, int, tl, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(lmsw, void, tl, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_0_M(clts, void, 0, 0, 0)
DEF_HELPER_2_M(movl_drN_T0, void, int, tl, 0, 0, 0)
DEF_HELPER_1_M(invlpg, void, tl, _RM_EXCP, _WM_EXCP, _AM_EXCP)

DEF_HELPER_3_M(enter_level, void, int, int, tl, _M_EBP | _M_ESP, 0, 1)
#ifdef TARGET_X86_64
DEF_HELPER_3(enter64_level, void, int, int, tl)
#endif
DEF_HELPER_0_M(sysenter, void, _RM_EXCP, _M_ESP | _WM_EXCP, 0)
DEF_HELPER_1_M(sysexit, void, int, _M_ECX | _M_EDX | _RM_EXCP, _M_ESP | _WM_EXCP, 0)
#ifdef TARGET_X86_64
DEF_HELPER_1(syscall, void, int)
DEF_HELPER_1(sysret, void, int)
#endif
DEF_HELPER_1_M(hlt, void, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(monitor, void, tl, _M_ECX | _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(mwait, void, int, _M_ECX | _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_0_M(debug, void, 0, 0, 0)
DEF_HELPER_0_M(reset_rf, void, 0, 0, 0)
DEF_HELPER_2_M(raise_interrupt, void, int, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(raise_exception, void, int, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_0_M(cli, void, 0, 0, 0)
DEF_HELPER_0_M(sti, void, 0, 0, 0)
DEF_HELPER_0_M(set_inhibit_irq, void, 0, 0, 0)
DEF_HELPER_0_M(reset_inhibit_irq, void, 0, 0, 0)
DEF_HELPER_2_M(boundw, void, tl, int, _RM_EXCP, _WM_EXCP, 1)
DEF_HELPER_2_M(boundl, void, tl, int, _RM_EXCP, _WM_EXCP, 1)
DEF_HELPER_0_M(rsm, void, (uint64_t) -1, (uint64_t) -1, 1)
DEF_HELPER_1_M(into, void, int, _RM_EXCP | _M_CC, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(cmpxchg8b, void, tl, _M_CC | _M_EAX | _M_EBX | _M_ECX | _M_EDX, _M_EAX | _M_EDX | _M_CC_SRC, 1)
#ifdef TARGET_X86_64
DEF_HELPER_1(cmpxchg16b, void, tl)
#endif
DEF_HELPER_0_M(single_step, void, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_0_M(cpuid, void, _RM_EXCP | _M_EAX | _M_ECX, _WM_EXCP | _M_EAX | _M_ECX | _M_EBX | _M_EDX, _AM_EXCP)
DEF_HELPER_0_M(rdtsc, void, _RM_EXCP, _WM_EXCP | _M_EAX | _M_EDX, _AM_EXCP)
DEF_HELPER_0_M(rdtscp, void, _RM_EXCP, _WM_EXCP | _M_EAX | _M_EDX | _M_ECX, _AM_EXCP)
DEF_HELPER_0_M(rdpmc, void, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_0_M(rdmsr, void, (uint64_t) -1, (uint64_t) -1, 0)
DEF_HELPER_0_M(wrmsr, void, (uint64_t) -1, (uint64_t) -1, 0)

DEF_HELPER_1_M(check_iob, void, i32, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(check_iow, void, i32, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_1_M(check_iol, void, i32, _RM_EXCP, _WM_EXCP, _AM_EXCP)
DEF_HELPER_2_M(outb, void, i32, i32, 0, 0, 0)
DEF_HELPER_1_M(inb, tl, i32, 0, 0, 0)
DEF_HELPER_2_M(outw, void, i32, i32, 0, 0, 0)
DEF_HELPER_1_M(inw, tl, i32, 0, 0, 0)
DEF_HELPER_2_M(outl, void, i32, i32, 0, 0, 0)
DEF_HELPER_1_M(inl, tl, i32, 0, 0, 0)

DEF_HELPER_2(svm_check_intercept_param, void, i32, i64)
DEF_HELPER_2(vmexit, void, i32, i64)
DEF_HELPER_3(svm_check_io, void, i32, i32, i32)
DEF_HELPER_2(vmrun, void, int, int)
DEF_HELPER_0(vmmcall, void)
DEF_HELPER_1(vmload, void, int)
DEF_HELPER_1(vmsave, void, int)
DEF_HELPER_0(stgi, void)
DEF_HELPER_0(clgi, void)
DEF_HELPER_0(skinit, void)
DEF_HELPER_1(invlpga, void, int)

/* x86 FPU */

DEF_HELPER_1(flds_FT0, void, i32)
DEF_HELPER_1(fldl_FT0, void, i64)
DEF_HELPER_1(fildl_FT0, void, s32)
DEF_HELPER_1(flds_ST0, void, i32)
DEF_HELPER_1(fldl_ST0, void, i64)
DEF_HELPER_1(fildl_ST0, void, s32)
DEF_HELPER_1(fildll_ST0, void, s64)
DEF_HELPER_0(fsts_ST0, i32)
DEF_HELPER_0(fstl_ST0, i64)
DEF_HELPER_0(fist_ST0, s32)
DEF_HELPER_0(fistl_ST0, s32)
DEF_HELPER_0(fistll_ST0, s64)
DEF_HELPER_0(fistt_ST0, s32)
DEF_HELPER_0(fisttl_ST0, s32)
DEF_HELPER_0(fisttll_ST0, s64)
DEF_HELPER_1(fldt_ST0, void, tl)
DEF_HELPER_1(fstt_ST0, void, tl)
DEF_HELPER_0(fpush, void)
DEF_HELPER_0(fpop, void)
DEF_HELPER_0(fdecstp, void)
DEF_HELPER_0(fincstp, void)
DEF_HELPER_1(ffree_STN, void, int)
DEF_HELPER_0(fmov_ST0_FT0, void)
DEF_HELPER_1(fmov_FT0_STN, void, int)
DEF_HELPER_1(fmov_ST0_STN, void, int)
DEF_HELPER_1(fmov_STN_ST0, void, int)
DEF_HELPER_1(fxchg_ST0_STN, void, int)
DEF_HELPER_0(fcom_ST0_FT0, void)
DEF_HELPER_0(fucom_ST0_FT0, void)
DEF_HELPER_0(fcomi_ST0_FT0, void)
DEF_HELPER_0(fucomi_ST0_FT0, void)
DEF_HELPER_0(fadd_ST0_FT0, void)
DEF_HELPER_0(fmul_ST0_FT0, void)
DEF_HELPER_0(fsub_ST0_FT0, void)
DEF_HELPER_0(fsubr_ST0_FT0, void)
DEF_HELPER_0(fdiv_ST0_FT0, void)
DEF_HELPER_0(fdivr_ST0_FT0, void)
DEF_HELPER_1(fadd_STN_ST0, void, int)
DEF_HELPER_1(fmul_STN_ST0, void, int)
DEF_HELPER_1(fsub_STN_ST0, void, int)
DEF_HELPER_1(fsubr_STN_ST0, void, int)
DEF_HELPER_1(fdiv_STN_ST0, void, int)
DEF_HELPER_1(fdivr_STN_ST0, void, int)
DEF_HELPER_0(fchs_ST0, void)
DEF_HELPER_0(fabs_ST0, void)
DEF_HELPER_0(fxam_ST0, void)
DEF_HELPER_0(fld1_ST0, void)
DEF_HELPER_0(fldl2t_ST0, void)
DEF_HELPER_0(fldl2e_ST0, void)
DEF_HELPER_0(fldpi_ST0, void)
DEF_HELPER_0(fldlg2_ST0, void)
DEF_HELPER_0(fldln2_ST0, void)
DEF_HELPER_0(fldz_ST0, void)
DEF_HELPER_0(fldz_FT0, void)
DEF_HELPER_0(fnstsw, i32)
DEF_HELPER_0(fnstcw, i32)
DEF_HELPER_1(fldcw, void, i32)
DEF_HELPER_0(fclex, void)
DEF_HELPER_0(fwait, void)
DEF_HELPER_0(fninit, void)
DEF_HELPER_1(fbld_ST0, void, tl)
DEF_HELPER_1(fbst_ST0, void, tl)
DEF_HELPER_0(f2xm1, void)
DEF_HELPER_0(fyl2x, void)
DEF_HELPER_0(fptan, void)
DEF_HELPER_0(fpatan, void)
DEF_HELPER_0(fxtract, void)
DEF_HELPER_0(fprem1, void)
DEF_HELPER_0(fprem, void)
DEF_HELPER_0(fyl2xp1, void)
DEF_HELPER_0(fsqrt, void)
DEF_HELPER_0(fsincos, void)
DEF_HELPER_0(frndint, void)
DEF_HELPER_0(fscale, void)
DEF_HELPER_0(fsin, void)
DEF_HELPER_0(fcos, void)
DEF_HELPER_2(fstenv, void, tl, int)
DEF_HELPER_2(fldenv, void, tl, int)
DEF_HELPER_2(fsave, void, tl, int)
DEF_HELPER_2(frstor, void, tl, int)
DEF_HELPER_2(fxsave, void, tl, int)
DEF_HELPER_2(fxrstor, void, tl, int)

DEF_HELPER_1_M(bsf, tl, tl, 0, 0, 0)
DEF_HELPER_1_M(bsr, tl, tl, 0, 0, 0)
DEF_HELPER_2_M(lzcnt, tl, tl, int, 0, 0, 0)

/* MMX/SSE */
DEF_HELPER_1_M(ldmxcsr, void, i32, 0, 0, 0)
DEF_HELPER_0_M(enter_mmx, void, 0, 0, 0)
DEF_HELPER_0_M(emms, void, 0, 0, 0)
DEF_HELPER_2_M(movq, void, ptr, ptr, 0, 0, 0)

#define SHIFT 0
#include "ops_sse_header.h"
#define SHIFT 1
#include "ops_sse_header.h"

DEF_HELPER_2_M(rclb, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rclw, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rcll, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rcrb, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rcrw, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rcrl, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
#ifdef TARGET_X86_64
DEF_HELPER_2_M(rclq, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
DEF_HELPER_2_M(rcrq, tl, tl, tl, _M_CC, _M_CC_TMP, 0)
#endif

#if !defined(CONFIG_SYMBEX)
DEF_HELPER_1_M(se_opcode, void, i64, 0, 0, 0)
#endif

#if defined(CONFIG_SYMBEX)
DEF_HELPER_1_M(se_call, void, tl, 0, 0, 0)
DEF_HELPER_1_M(se_ret, void, tl, 0, 0, 0)
#endif

#include "def-helper.h"
