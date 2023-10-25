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

#ifndef __LIBCPU_I386_CPU_H__

#define __LIBCPU_I386_CPU_H__

#ifndef CPUArchState
#define CPUArchState struct CPUX86State
#endif

#include <cpu/common.h>
#include <cpu/interrupt.h>
#include <cpu/types.h>
#include <fpu/softfloat.h>
#include <stdbool.h>
#include "cpuid.h"
#include "defs.h"

#include <tcg/regs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

#ifdef TARGET_X86_64
#define CPU_NB_REGS CPU_NB_REGS64
#else
#define CPU_NB_REGS CPU_NB_REGS32
#endif

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];

    /* emulator internal eflags handling */
    /* The order must match _M_CC_*** constants in helper.h */
    target_ulong cc_op; /* target_ulong for uniform alignment */
    target_ulong cc_src;
    target_ulong cc_dst;
    target_ulong cc_tmp; /* temporary for rcr/rcl */

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8]; /* 0 = valid, 1 = empty */
    FPReg fpregs[8];

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    XMMReg xmm_regs[CPU_NB_REGS];
    XMMReg xmm_t0;
    MMXReg mmx_t0;

    /* symbex note: the contents of the structure from this point
       can never be symbolic. */
    target_ulong eip;

    int32_t df;          /* D flag : 1 if D = 0, -1 if D = 1 */
    target_ulong mflags; /* Mode and control flags from eflags */

    uint32_t hflags;  /* TB flags, see HF_xxx constants. These flags
                         are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    target_ulong return_address; /* Return address on call */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t efer;
    uint64_t star;

    uint64_t vm_hsave;
    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint8_t v_tpr;
    uint8_t v_apic_tpr;
    uint64_t v_apic_base;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif
    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t async_pf_en_msr;

    uint64_t tsc;
    uint64_t tsc_deadline;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers */
    union {
        CPUBreakpoint *cpu_breakpoint[4];
        CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    uint32_t smbase;
    int old_exception; /* exception in flight */

    uint8_t timer_interrupt_disabled;
    uint8_t all_apic_interrupts_disabled;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    CPU_COMMON

    uint64_t pat;

    /* processor features (e.g. for CPUID insn) */
    struct cpuid_t cpuid;

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[8];

    /* For KVM */
    int kvm_request_interrupt_window;
    int kvm_irq;

    /* in order to simplify APIC support, we leave this pointer to the
       user */
    struct DeviceState *apic_state;

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF * 4];

    uint64_t tsc_aux;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;

    uint64_t xstate_bv;
    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t xcr0;

    TPRAccess tpr_access_type;

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
    target_ulong precise_eip;
#endif
} CPUX86State;

void do_cpu_init(CPUX86State *env);

CPUX86State *cpu_x86_init(const cpuid_t *cpuid);
int cpu_x86_exec(CPUX86State *s);

static inline bool cpu_has_work(CPUX86State *env) {
    return ((env->interrupt_request & CPU_INTERRUPT_HARD) && (env->mflags & IF_MASK)) ||
           (env->interrupt_request & (CPU_INTERRUPT_NMI | CPU_INTERRUPT_INIT | CPU_INTERRUPT_SIPI | CPU_INTERRUPT_MCE));
}

target_ulong cpu_get_eflags(CPUX86State *env);
void cpu_restore_eflags(CPUX86State *env);

static inline int cpu_mmu_index(CPUX86State *env) {
    return (env->hflags & HF_CPL_MASK) == 3 ? 1 : 0;
}

int check_hw_breakpoints(CPUX86State *env, int force_dr6_update);

void hw_breakpoint_insert(CPUX86State *env, int index);
void hw_breakpoint_remove(CPUX86State *env, int index);

/* will be suppressed */
void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0);
void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3);
void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4);

int cpu_x86_handle_mmu_fault(CPUX86State *env, target_ulong addr, int is_write, int mmu_idx);

void cpu_set_eflags(CPUX86State *env, target_ulong eflags);

uint32_t cpu_compute_hflags(const CPUX86State *env);

#ifdef __cplusplus
}
#endif

#endif
