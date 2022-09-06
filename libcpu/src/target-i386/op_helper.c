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

#include <cpu/ioport.h>
#include <math.h>
#include <timer.h>
#include "cpu-defs.h"
#include "cpu.h"

#include <tcg/tcg-op.h>

#include <tcg/utils/host-utils.h>
#include "libcpu-log.h"

#include "softmmu_exec.h"

// SYMBEX: Keep the environment in a variable
struct CPUX86State *env = 0;

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
#include <cpu/softmmu_defs.h>

#define ACCESS_TYPE 0
#define MEMSUFFIX   _kernel_symb
#define _raw        _raw_symb
#define DATA_SIZE   1
#include "softmmu_header.h"

#define DATA_SIZE 2
#include "softmmu_header.h"

#define DATA_SIZE 4
#include "softmmu_header.h"

#define DATA_SIZE 8
#include "softmmu_header.h"
#undef _raw
#undef ACCESS_TYPE
#undef MEMSUFFIX

#endif

//#define DEBUG_PCALL

#ifdef DEBUG_PCALL
#define LOG_PCALL(...)       libcpu_log_mask(CPU_LOG_PCALL, ##__VA_ARGS__)
#define LOG_PCALL_STATE(env) log_cpu_state_mask(CPU_LOG_PCALL, (env), X86_DUMP_CCOP)
#else
#define LOG_PCALL(...) \
    do {               \
    } while (0)
#define LOG_PCALL_STATE(env) \
    do {                     \
    } while (0)
#endif

/* n must be a constant to be efficient */
static inline target_long lshift(target_long x, int n) {
    if (n >= 0) {
        return x << n;
    } else {
        return x >> (-n);
    }
}

#define FPU_RC_MASK 0xc00
#define FPU_RC_NEAR 0x000
#define FPU_RC_DOWN 0x400
#define FPU_RC_UP   0x800
#define FPU_RC_CHOP 0xc00

#define MAXTAN 9223372036854775808.0

/* the following deal with x86 long double-precision numbers */
#define MAXEXPD          0x7fff
#define EXPBIAS          16383
#define EXPD(fp)         (fp.l.upper & 0x7fff)
#define SIGND(fp)        ((fp.l.upper) & 0x8000)
#define MANTD(fp)        (fp.l.lower)
#define BIASEXPONENT(fp) fp.l.upper = (fp.l.upper & ~(0x7fff)) | EXPBIAS

static inline void fpush(void) {
    FPSTT_W((FPSTT - 1) & 7);
    FPTAGS_W(FPSTT, 0); /* validate stack entry */
}

static inline void fpop(void) {
    FPTAGS_W(FPSTT, 1); /* invvalidate stack entry */
    FPSTT_W((FPSTT + 1) & 7);
}

static inline floatx80 helper_fldt(target_ulong ptr) {
    CPU_LDoubleU temp;

    temp.l.lower = ldq(ptr);
    temp.l.upper = lduw(ptr + 8);
    return temp.d;
}

static inline void helper_fstt(floatx80 f, target_ulong ptr) {
    CPU_LDoubleU temp;

    temp.d = f;
    stq(ptr, temp.l.lower);
    stw(ptr + 8, temp.l.upper);
}

#define FPUS_IE (1 << 0)
#define FPUS_DE (1 << 1)
#define FPUS_ZE (1 << 2)
#define FPUS_OE (1 << 3)
#define FPUS_UE (1 << 4)
#define FPUS_PE (1 << 5)
#define FPUS_SF (1 << 6)
#define FPUS_SE (1 << 7)
#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

uint32_t compute_eflags(void) {
    // Bit 1 must always be set according to x86 architecture
    // The cast to uint32_t is required to reduce the complexity of LLVM instructions,
    // which would otherwise create deep expression trees during symbolic execution
    // (chains of extract/zext).
    return ((uint32_t) env->mflags) | helper_cc_compute_all(CC_OP) | (DF & DF_MASK) | 2;
}

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
static inline void se_load_eflags(void *mgr, void *eflags, int update_mask) {
    void *symb_flags = g_sqi.expr.andc(mgr, eflags, CFLAGS_MASK);
    g_sqi.expr.write_cpu(symb_flags, offsetof(CPUX86State, cc_src), sizeof(env->cc_src));

    void *symb_df = g_sqi.expr.andc(mgr, eflags, DF_MASK);
    uint64_t concrete_df = g_sqi.expr.to_constant(symb_df);
    DF_W(concrete_df ? -1 : 1);

    uint64_t concrete_flags = g_sqi.expr.to_constant(g_sqi.expr.andc(mgr, eflags, MFLAGS_MASK & update_mask));

    env->mflags = (env->mflags & ~update_mask) | concrete_flags;
}

#endif

/* NOTE: CC_OP must be modified manually to CC_OP_EFLAGS */
static inline void load_eflags(int eflags, int update_mask) {
    CC_SRC_W(eflags & CFLAGS_MASK);
    DF_W((eflags & DF_MASK) ? -1 : 1);
    /*
    WR_cpu(env, eflags, (RR_cpu(env, eflags) & ~update_mask) |
        (eflags & update_mask) | 0x2);
    */

    env->mflags = (env->mflags & ~update_mask) | (eflags & MFLAGS_MASK & update_mask);

#if 0
    //Original QEMU code
    CC_SRC_W(eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C));
    DF_W(1 - (2 * ((eflags >> 10) & 1)));
    env->eflags = (env->eflags & ~update_mask) |
        (eflags & update_mask) | 0x2;
#endif
}

/* TODO: remove duplication with load_eflags ? */
void cpu_set_eflags(CPUX86State *env, target_ulong eflags) {
    WR_cpu(env, cc_op, CC_OP_EFLAGS);
    WR_cpu(env, cc_src, eflags & CFLAGS_MASK);
    env->df = (eflags & DF_MASK) ? -1 : 1;
    env->mflags = eflags & MFLAGS_MASK;
}

/* load efer and update the corresponding hflags. XXX: do consistency
   checks with cpuid bits ? */
static inline void cpu_load_efer(CPUX86State *env, uint64_t val) {
    env->efer = val;
    env->hflags &= ~(HF_LMA_MASK | HF_SVME_MASK);
    if (env->efer & MSR_EFER_LMA) {
        env->hflags |= HF_LMA_MASK;
    }
    if (env->efer & MSR_EFER_SVME) {
        env->hflags |= HF_SVME_MASK;
    }
}

#if !defined(SYMBEX_LLVM_LIB) || defined(STATIC_TRANSLATOR)

const uint8_t parity_table[256] = {
    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P,
    0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P, 0,
    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,
    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P,
    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P, 0,    0,
    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P,
    CC_P, 0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P,
    0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,
    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P,
    0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P,
    CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,
    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    0,    CC_P, CC_P, 0,
    CC_P, 0,    0,    CC_P, CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P, 0,    CC_P, CC_P,
    0,    0,    CC_P, CC_P, 0,    CC_P, 0,    0,    CC_P,
};

/* modulo 17 table */
const uint8_t rclw_table[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
};

/* modulo 9 table */
const uint8_t rclb_table[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4,
};

#else
extern const uint8_t parity_table[256];
extern const uint8_t rclw_table[32];
extern const uint8_t rclb_table[32];
#endif

#define floatx80_lg2 make_floatx80(0x3ffd, 0x9a209a84fbcff799LL)
#define floatx80_l2e make_floatx80(0x3fff, 0xb8aa3b295c17f0bcLL)
#define floatx80_l2t make_floatx80(0x4000, 0xd49a784bcd1b8afeLL)

/* broken thread support */
#if !defined(SYMBEX_LLVM_LIB) || defined(STATIC_TRANSLATOR)
// static spinlock_t global_cpu_lock = SPIN_LOCK_UNLOCKED;

/**
 * XXX: don't use any locking at all, it's broken.
 * Locked memory accesses can exit the cpu loop, so the
 * unlock will never get done.
 * We don't need locking on single cpu anyway.
 */
void helper_lock(void) {
#ifndef STATIC_TRANSLATOR
// spin_lock(&global_cpu_lock);
#endif
}

void helper_unlock(void) {
#ifndef STATIC_TRANSLATOR
// spin_unlock(&global_cpu_lock);
#endif
}
#endif /* SYMBEX_LLVM_LIB */

void helper_write_eflags(target_ulong t0, uint32_t update_mask) {
    load_eflags(t0, update_mask);
}

target_ulong helper_read_eflags(void) {
    uint32_t eflags;
    eflags = helper_cc_compute_all(CC_OP);
    eflags |= (DF & DF_MASK);
    eflags |= env->mflags & ~(VM_MASK | RF_MASK);
    return eflags;
}

/* return non zero if error */
static inline int load_segment(uint32_t *e1_ptr, uint32_t *e2_ptr, int selector) {
    SegmentCache *dt;
    int index;
    target_ulong ptr;

    if (selector & 0x4)
        dt = &env->ldt;
    else
        dt = &env->gdt;
    index = selector & ~7;
    if ((index + 7) > dt->limit)
        return -1;
    ptr = dt->base + index;
    *e1_ptr = cpu_ldl_kernel(env, ptr);
    *e2_ptr = cpu_ldl_kernel(env, ptr + 4);
    return 0;
}

static inline unsigned int get_seg_limit(uint32_t e1, uint32_t e2) {
    unsigned int limit;
    limit = (e1 & 0xffff) | (e2 & 0x000f0000);
    if (e2 & DESC_G_MASK)
        limit = (limit << 12) | 0xfff;
    return limit;
}

static inline uint32_t get_seg_base(uint32_t e1, uint32_t e2) {
    return ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));
}

static inline void load_seg_cache_raw_dt(SegmentCache *sc, uint32_t e1, uint32_t e2) {
    sc->base = get_seg_base(e1, e2);
    sc->limit = get_seg_limit(e1, e2);
    sc->flags = e2;
}

/* init the segment cache in vm86 mode. */
static inline void load_seg_vm(int seg, int selector) {
    selector &= 0xffff;
    cpu_x86_load_seg_cache(env, seg, selector, (selector << 4), 0xffff, 0);
}

static inline void get_ss_esp_from_tss(CPUX86State *env, uint32_t *ss_ptr, uint32_t *esp_ptr, int dpl,
                                       uintptr_t retaddr) {
    int type, index, shift;

#if 0
    {
        int i;
        printf("TR: base=%p limit=%x\n", env->tr.base, env->tr.limit);
        for(i=0;i<env->tr.limit;i++) {
            printf("%02x ", env->tr.base[i]);
            if ((i & 7) == 7) printf("\n");
        }
        printf("\n");
    }
#endif

    if (!(env->tr.flags & DESC_P_MASK))
        cpu_abort(env, "invalid tss");
    type = (env->tr.flags >> DESC_TYPE_SHIFT) & 0xf;

    // XXX: this seems to fire when resuming KVM snapshots
    // in DBT mode. Not sure why this check is useful in the
    // context from which this function is called.
    // if ((type & 7) != 1)
    //    cpu_abort(env, "invalid tss type");

    shift = type >> 3;
    index = (dpl * 4 + 2) << shift;
    if (index + (4 << shift) - 1 > env->tr.limit)
        raise_exception_err_ra(env, EXCP0A_TSS, env->tr.selector & 0xfffc, retaddr);
    if (shift == 0) {
        *esp_ptr = cpu_lduw_kernel(env, env->tr.base + index);
        *ss_ptr = cpu_lduw_kernel(env, env->tr.base + index + 2);
    } else {
        *esp_ptr = cpu_ldl_kernel(env, env->tr.base + index);
        *ss_ptr = cpu_lduw_kernel(env, env->tr.base + index + 4);
    }
}

/* XXX: merge with load_seg() */
static void tss_load_seg(CPUX86State *env, int seg_reg, int selector, uintptr_t ra) {
    uint32_t e1, e2;
    int rpl, dpl, cpl;

    if ((selector & 0xfffc) != 0) {
        if (load_segment(&e1, &e2, selector) != 0)
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
        if (!(e2 & DESC_S_MASK))
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
        rpl = selector & 3;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        cpl = env->hflags & HF_CPL_MASK;
        if (seg_reg == R_CS) {
            if (!(e2 & DESC_CS_MASK))
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
            /* XXX: is it correct ? */
            if (dpl != rpl)
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
            if ((e2 & DESC_C_MASK) && dpl > rpl)
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
        } else if (seg_reg == R_SS) {
            /* SS must be writable data */
            if ((e2 & DESC_CS_MASK) || !(e2 & DESC_W_MASK))
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
            if (dpl != cpl || dpl != rpl)
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
        } else {
            /* not readable code */
            if ((e2 & DESC_CS_MASK) && !(e2 & DESC_R_MASK))
                raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
            /* if data or non conforming code, checks the rights */
            if (((e2 >> DESC_TYPE_SHIFT) & 0xf) < 12) {
                if (dpl < cpl || dpl < rpl)
                    raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
            }
        }
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, ra);
        cpu_x86_load_seg_cache(env, seg_reg, selector, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
    } else {
        if (seg_reg == R_SS || seg_reg == R_CS)
            raise_exception_err_ra(env, EXCP0A_TSS, selector & 0xfffc, ra);
    }
}

#define SWITCH_TSS_JMP  0
#define SWITCH_TSS_IRET 1
#define SWITCH_TSS_CALL 2

/* XXX: restore CPU state in registers (PowerPC case) */
static void switch_tss(CPUX86State *env, int tss_selector, uint32_t e1, uint32_t e2, int source, uint32_t next_eip,
                       uintptr_t ra) {
    int tss_limit, tss_limit_max, type, old_tss_limit_max, old_type, v1, v2, i;
    target_ulong tss_base;
    uint32_t new_regs[8], new_segs[6];
    uint32_t new_eflags, new_eip, new_cr3, new_ldt, new_trap;
    uint32_t old_eflags, eflags_mask;
    SegmentCache *dt;
    int index;
    target_ulong ptr;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int cpl = env->hflags & HF_CPL_MASK;
#endif

    type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
    LOG_PCALL("switch_tss: sel=0x%04x type=%d src=%d\n", tss_selector, type, source);

    /* if task gate, we read the TSS segment and we load it */
    if (type == 5) {
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, tss_selector & 0xfffc, ra);
        tss_selector = e1 >> 16;
        if (tss_selector & 4)
            raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, ra);
        if (load_segment(&e1, &e2, tss_selector) != 0)
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, ra);
        if (e2 & DESC_S_MASK)
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, ra);
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        if ((type & 7) != 1)
            raise_exception_err_ra(env, EXCP0D_GPF, tss_selector & 0xfffc, ra);
    }

    if (!(e2 & DESC_P_MASK))
        raise_exception_err_ra(env, EXCP0B_NOSEG, tss_selector & 0xfffc, ra);

    if (type & 8)
        tss_limit_max = 103;
    else
        tss_limit_max = 43;
    tss_limit = get_seg_limit(e1, e2);
    tss_base = get_seg_base(e1, e2);
    if ((tss_selector & 4) != 0 || tss_limit < tss_limit_max)
        raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, ra);
    old_type = (env->tr.flags >> DESC_TYPE_SHIFT) & 0xf;
    if (old_type & 8)
        old_tss_limit_max = 103;
    else
        old_tss_limit_max = 43;

    /* read all the registers from the new TSS */
    if (type & 8) {
        /* 32 bit */
        new_cr3 = cpu_ldl_kernel(env, tss_base + 0x1c);
        new_eip = cpu_ldl_kernel(env, tss_base + 0x20);
        new_eflags = cpu_ldl_kernel(env, tss_base + 0x24);
        for (i = 0; i < 8; i++)
            new_regs[i] = cpu_ldl_kernel(env, tss_base + (0x28 + i * 4));
        for (i = 0; i < 6; i++)
            new_segs[i] = cpu_lduw_kernel(env, tss_base + (0x48 + i * 4));
        new_ldt = cpu_lduw_kernel(env, tss_base + 0x60);
        new_trap = cpu_ldl_kernel(env, tss_base + 0x64);
    } else {
        /* 16 bit */
        new_cr3 = 0;
        new_eip = cpu_lduw_kernel(env, tss_base + 0x0e);
        new_eflags = cpu_lduw_kernel(env, tss_base + 0x10);
        for (i = 0; i < 8; i++)
            new_regs[i] = cpu_lduw_kernel(env, tss_base + (0x12 + i * 2)) | 0xffff0000;
        for (i = 0; i < 4; i++)
            new_segs[i] = cpu_lduw_kernel(env, tss_base + (0x22 + i * 4));
        new_ldt = cpu_lduw_kernel(env, tss_base + 0x2a);
        new_segs[R_FS] = 0;
        new_segs[R_GS] = 0;
        new_trap = 0;
    }
    /* XXX: avoid a compiler warning, see
     http://support.amd.com/us/Processor_TechDocs/24593.pdf
     chapters 12.2.5 and 13.2.4 on how to implement TSS Trap bit */
    (void) new_trap;

    /* NOTE: we must avoid memory exceptions during the task switch,
       so we make dummy accesses before */
    /* XXX: it can still fail in some cases, so a bigger hack is
       necessary to valid the TLB after having done the accesses */

    v1 = cpu_ldub_kernel(env, env->tr.base);
    v2 = cpu_ldub_kernel(env, env->tr.base + old_tss_limit_max);
    cpu_stb_kernel(env, env->tr.base, v1);
    cpu_stb_kernel(env, env->tr.base + old_tss_limit_max, v2);

    /* clear busy bit (it is restartable) */
    if (source == SWITCH_TSS_JMP || source == SWITCH_TSS_IRET) {
        target_ulong ptr;
        uint32_t e2;
        ptr = env->gdt.base + (env->tr.selector & ~7);
        e2 = cpu_ldl_kernel(env, ptr + 4);
        e2 &= ~DESC_TSS_BUSY_MASK;
        cpu_stl_kernel(env, ptr + 4, e2);
    }
    old_eflags = compute_eflags();
    if (source == SWITCH_TSS_IRET)
        old_eflags &= ~NT_MASK;

    /* save the current state in the old TSS */
    if (type & 8) {
        /* 32 bit */
        cpu_stl_kernel(env, env->tr.base + 0x20, next_eip);
        cpu_stl_kernel(env, env->tr.base + 0x24, old_eflags);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 0 * 4), EAX);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 1 * 4), ECX);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 2 * 4), EDX);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 3 * 4), EBX);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 4 * 4), ESP);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 5 * 4), EBP);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 6 * 4), ESI);
        cpu_stl_kernel(env, env->tr.base + (0x28 + 7 * 4), EDI);
        for (i = 0; i < 6; i++)
            cpu_stw_kernel(env, env->tr.base + (0x48 + i * 4), env->segs[i].selector);
    } else {
        /* 16 bit */
        cpu_stw_kernel(env, env->tr.base + 0x0e, next_eip);
        cpu_stw_kernel(env, env->tr.base + 0x10, old_eflags);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 0 * 2), EAX);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 1 * 2), ECX);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 2 * 2), EDX);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 3 * 2), EBX);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 4 * 2), ESP);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 5 * 2), EBP);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 6 * 2), ESI);
        cpu_stw_kernel(env, env->tr.base + (0x12 + 7 * 2), EDI);
        for (i = 0; i < 4; i++)
            cpu_stw_kernel(env, env->tr.base + (0x22 + i * 4), env->segs[i].selector);
    }

    /* now if an exception occurs, it will occurs in the next task
       context */

    if (source == SWITCH_TSS_CALL) {
        cpu_stw_kernel(env, tss_base, env->tr.selector);
        new_eflags |= NT_MASK;
    }

    /* set busy bit */
    if (source == SWITCH_TSS_JMP || source == SWITCH_TSS_CALL) {
        target_ulong ptr;
        uint32_t e2;
        ptr = env->gdt.base + (tss_selector & ~7);
        e2 = cpu_ldl_kernel(env, ptr + 4);
        e2 |= DESC_TSS_BUSY_MASK;
        cpu_stl_kernel(env, ptr + 4, e2);
    }

    /* set the new CPU state */
    /* from this point, any exception which occurs can give problems */
    env->cr[0] |= CR0_TS_MASK;
    env->hflags |= HF_TS_MASK;
    env->tr.selector = tss_selector;
    env->tr.base = tss_base;
    env->tr.limit = tss_limit;
    env->tr.flags = e2 & ~DESC_TSS_BUSY_MASK;

    if ((type & 8) && (env->cr[0] & CR0_PG_MASK)) {
        cpu_x86_update_cr3(env, new_cr3);
    }

    /* load all registers without an exception, then reload them with
       possible exception */
    env->eip = new_eip;
    WR_se_eip(env, new_eip);
    eflags_mask = TF_MASK | AC_MASK | ID_MASK | IF_MASK | IOPL_MASK | VM_MASK | RF_MASK | NT_MASK;
    if (!(type & 8))
        eflags_mask &= 0xffff;
    load_eflags(new_eflags, eflags_mask);
    /* XXX: what to do in 16 bit case ? */
    EAX_W(new_regs[0]);
    ECX_W(new_regs[1]);
    EDX_W(new_regs[2]);
    EBX_W(new_regs[3]);
    ESP_W(new_regs[4]);
    EBP_W(new_regs[5]);
    ESI_W(new_regs[6]);
    EDI_W(new_regs[7]);

    int dpl;
    if (new_eflags & VM_MASK) {
        for (i = 0; i < 6; i++)
            load_seg_vm(i, new_segs[i]);
        /* in vm86, CPL is always 3 */
        dpl = 3;
        cpu_x86_set_cpl(env, dpl);
    } else {
        /* CPL is set the RPL of CS */
        dpl = new_segs[R_CS] & 3;
        cpu_x86_set_cpl(env, dpl);
        /* first just selectors as the rest may trigger exceptions */
        for (i = 0; i < 6; i++)
            cpu_x86_load_seg_cache(env, i, new_segs[i], 0, 0, 0);
    }

    env->ldt.selector = new_ldt & ~4;
    env->ldt.base = 0;
    env->ldt.limit = 0;
    env->ldt.flags = 0;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, dpl);
    }
#endif

    /* load the LDT */
    if (new_ldt & 4)
        raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, ra);

    if ((new_ldt & 0xfffc) != 0) {
        dt = &env->gdt;
        index = new_ldt & ~7;
        if ((index + 7) > dt->limit)
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, ra);
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel(env, ptr);
        e2 = cpu_ldl_kernel(env, ptr + 4);
        if ((e2 & DESC_S_MASK) || ((e2 >> DESC_TYPE_SHIFT) & 0xf) != 2)
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, ra);
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0A_TSS, new_ldt & 0xfffc, ra);
        load_seg_cache_raw_dt(&env->ldt, e1, e2);
    }

    /* load the segments */
    if (!(new_eflags & VM_MASK)) {
        tss_load_seg(env, R_CS, new_segs[R_CS], ra);
        tss_load_seg(env, R_SS, new_segs[R_SS], ra);
        tss_load_seg(env, R_ES, new_segs[R_ES], ra);
        tss_load_seg(env, R_DS, new_segs[R_DS], ra);
        tss_load_seg(env, R_FS, new_segs[R_FS], ra);
        tss_load_seg(env, R_GS, new_segs[R_GS], ra);
    }

    /* check that EIP is in the CS segment limits */
    if (new_eip > env->segs[R_CS].limit) {
        /* XXX: different exception if CALL ? */
        raise_exception_err(env, EXCP0D_GPF, 0);
    }

    /* reset local breakpoints */
    if (env->dr[7] & 0x55) {
        for (i = 0; i < 4; i++) {
            if (hw_breakpoint_enabled(env->dr[7], i) == 0x1)
                hw_breakpoint_remove(env, i);
        }
        env->dr[7] &= ~0x55;
    }
}

/* check if Port I/O is allowed in TSS */
static inline void check_io(CPUX86State *env, int addr, int size, uintptr_t ra) {
    int io_offset, val, mask;

    /* TSS must be a valid 32 bit one */
    if (!(env->tr.flags & DESC_P_MASK) || ((env->tr.flags >> DESC_TYPE_SHIFT) & 0xf) != 9 || env->tr.limit < 103)
        goto fail;
    io_offset = cpu_lduw_kernel(env, env->tr.base + 0x66);
    io_offset += (addr >> 3);
    /* Note: the check needs two bytes */
    if ((io_offset + 1) > env->tr.limit)
        goto fail;
    val = cpu_lduw_kernel(env, env->tr.base + io_offset);
    val >>= (addr & 7);
    mask = (1 << size) - 1;
    /* all bits must be zero to allow the I/O */
    if ((val & mask) != 0) {
    fail:
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
}

void helper_check_iob(uint32_t t0) {
    check_io(env, t0, 1, GETPC());
}

void helper_check_iow(uint32_t t0) {
    check_io(env, t0, 2, GETPC());
}

void helper_check_iol(uint32_t t0) {
    check_io(env, t0, 4, GETPC());
}

#ifdef STATIC_TRANSLATOR
void helper_outb(uint32_t port, uint32_t data) {
    assert(0);
}

target_ulong helper_inb(uint32_t port) {
    assert(0);
}

void helper_outw(uint32_t port, uint32_t data) {
    assert(0);
}

target_ulong helper_inw(uint32_t port) {
    assert(0);
}

void helper_outl(uint32_t port, uint32_t data) {
    assert(0);
}

target_ulong helper_inl(uint32_t port) {
    assert(0);
}

#else

#ifdef SYMBEX_LLVM_LIB
/**
 *  We bypass the call to the handlers in case of writes to symbolic ports to
 *  avoid concretizing data unnecessarily.
 */

void helper_outb(uint32_t port, uint32_t data) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    if (tcg_llvm_trace_port_access(port, data, 8, 1)) {
        if (*g_sqi.mode.concretize_io_writes) {
            data &= 0xFF;
            data = tcg_llvm_get_value(data, false);
        }
        cpu_outb(port, data & 0xff);
    }
}

target_ulong helper_inb(uint32_t port) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    target_ulong res = cpu_inb(port);
    return tcg_llvm_trace_port_access(port, res, 8, 0);
}

void helper_outw(uint32_t port, uint32_t data) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    if (tcg_llvm_trace_port_access(port, data, 16, 1)) {
        if (*g_sqi.mode.concretize_io_writes) {
            data &= 0xFFFF;
            data = tcg_llvm_get_value(data, false);
        }
        cpu_outw(port, data & 0xffff);
    }
}

target_ulong helper_inw(uint32_t port) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    target_ulong res = cpu_inw(port);
    return tcg_llvm_trace_port_access(port, res, 16, 0);
}

void helper_outl(uint32_t port, uint32_t data) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    if (tcg_llvm_trace_port_access(port, data, 32, 1)) {
        if (*g_sqi.mode.concretize_io_writes) {
            data = tcg_llvm_get_value(data, false);
        }
        cpu_outl(port, data);
    }
}

target_ulong helper_inl(uint32_t port) {
    if (*g_sqi.mode.concretize_io_addresses) {
        port = tcg_llvm_get_value(port, false);
    }

    target_ulong res = cpu_inl(port);
    return tcg_llvm_trace_port_access(port, res, 32, 0);
}
#else

void helper_outb(uint32_t port, uint32_t data) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, data, 8, 1, (void *) GETPC());
    }
#endif
    cpu_outb(port, data & 0xff);
}

target_ulong helper_inb(uint32_t port) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
#endif
    target_ulong res = cpu_inb(port);
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, res, 8, 0, (void *) GETPC());
    }
#endif
    return res;
}

void helper_outw(uint32_t port, uint32_t data) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, data, 16, 1, (void *) GETPC());
    }
#endif
    cpu_outw(port, data & 0xffff);
}

target_ulong helper_inw(uint32_t port) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
#endif
    target_ulong res = cpu_inw(port);
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, res, 16, 0, (void *) GETPC());
    }
#endif
    return res;
}

void helper_outl(uint32_t port, uint32_t data) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }

    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, data, 32, 1, (void *) GETPC());
    }
#endif
    cpu_outl(port, data);
}

target_ulong helper_inl(uint32_t port) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (g_sqi.mem.is_port_symbolic(port)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
#endif
    target_ulong res = cpu_inl(port);
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (*g_sqi.events.on_port_access_signals_count) {
        g_sqi.events.trace_port_access(port, res, 32, 0, (void *) GETPC());
    }
#endif
    return res;
}

#endif

#endif /* STATIC_TRANSLATOR */

static inline unsigned int get_sp_mask(unsigned int e2) {
    if (e2 & DESC_B_MASK)
        return 0xffffffff;
    else
        return 0xffff;
}

static int exeption_has_error_code(int intno) {
    switch (intno) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            return 1;
    }
    return 0;
}

#ifdef TARGET_X86_64
#define SET_ESP(val, sp_mask)                         \
    do {                                              \
        if ((sp_mask) == 0xffff)                      \
            ESP_W((ESP & ~0xffff) | ((val) &0xffff)); \
        else if ((sp_mask) == 0xffffffffLL)           \
            ESP_W((uint32_t) (val));                  \
        else                                          \
            ESP_W(val);                               \
    } while (0)
#else
#define SET_ESP(val, sp_mask) ESP_W((ESP & ~(sp_mask)) | ((val) & (sp_mask)))
#endif

/* in 64-bit machines, this can overflow. So this segment addition macro
 * can be used to trim the value to 32-bit whenever needed */
#define SEG_ADDL(ssp, sp, sp_mask) ((uint32_t) ((ssp) + (sp & (sp_mask))))

/* XXX: add a is_user flag to have proper security support */
#define PUSHW(ssp, sp, sp_mask, val)                          \
    {                                                         \
        sp -= 2;                                              \
        cpu_stw_kernel(env, (ssp) + (sp & (sp_mask)), (val)); \
    }

#define PUSHL(ssp, sp, sp_mask, val)                                       \
    {                                                                      \
        sp -= 4;                                                           \
        cpu_stl_kernel(env, SEG_ADDL(ssp, sp, sp_mask), (uint32_t) (val)); \
    }

#define POPW(ssp, sp, sp_mask, val)                           \
    {                                                         \
        val = cpu_lduw_kernel(env, (ssp) + (sp & (sp_mask))); \
        sp += 2;                                              \
    }

#define POPL(ssp, sp, sp_mask, val)                                       \
    {                                                                     \
        val = (uint32_t) cpu_ldl_kernel(env, SEG_ADDL(ssp, sp, sp_mask)); \
        sp += 4;                                                          \
    }

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
#define POPW_T(ssp, sp, sp_mask, val)                         \
    {                                                         \
        val = cpu_lduw_kernel(env, (ssp) + (sp & (sp_mask))); \
        sp += 2;                                              \
    }

#define POPL_T(ssp, sp, sp_mask, val)                                     \
    {                                                                     \
        val = (uint32_t) cpu_ldl_kernel(env, SEG_ADDL(ssp, sp, sp_mask)); \
        sp += 4;                                                          \
    }

#define POPL_T_S(mgr, ssp, sp, sp_mask, val)                          \
    {                                                                 \
        val = g_sqi.expr.read_mem_l(mgr, SEG_ADDL(ssp, sp, sp_mask)); \
        sp += 4;                                                      \
    }
#else
#define POPW_T(ssp, sp, sp_mask, val) POPW(ssp, sp, sp_mask, val)
#define POPL_T(ssp, sp, sp_mask, val) POPL(ssp, sp, sp_mask, val)
#endif

/* protected mode interrupt */
static void do_interrupt_protected(CPUX86State *env, int intno, int is_int, int error_code, unsigned int next_eip,
                                   int is_hw) {
    SegmentCache *dt;
    target_ulong ptr, ssp;
    int type, dpl, selector, ss_dpl, cpl;
    int has_error_code, new_stack, shift;
    uint32_t e1, e2, offset, ss = 0, esp, ss_e1 = 0, ss_e2 = 0;
    uint32_t old_eip, sp_mask;

    has_error_code = 0;
    if (!is_int && !is_hw)
        has_error_code = exeption_has_error_code(intno);
    if (is_int)
        old_eip = next_eip;
    else
        old_eip = env->eip;

    dt = &env->idt;
    if (intno * 8 + 7 > dt->limit)
        raise_exception_err(env, EXCP0D_GPF, intno * 8 + 2);
    ptr = dt->base + intno * 8;
    e1 = cpu_ldl_kernel(env, ptr);
    e2 = cpu_ldl_kernel(env, ptr + 4);
    /* check gate type */
    type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
    switch (type) {
        case 5: /* task gate */
            /* must do that check here to return the correct error code */
            if (!(e2 & DESC_P_MASK))
                raise_exception_err(env, EXCP0B_NOSEG, intno * 8 + 2);
            switch_tss(env, intno * 8, e1, e2, SWITCH_TSS_CALL, old_eip, 0);
            if (has_error_code) {
                int type;
                uint32_t mask;
                /* push the error code */
                type = (env->tr.flags >> DESC_TYPE_SHIFT) & 0xf;
                shift = type >> 3;
                if (env->segs[R_SS].flags & DESC_B_MASK)
                    mask = 0xffffffff;
                else
                    mask = 0xffff;
                esp = (ESP - (2 << shift)) & mask;
                ssp = env->segs[R_SS].base + esp;
                if (shift)
                    cpu_stl_kernel(env, ssp, error_code);
                else
                    cpu_stw_kernel(env, ssp, error_code);
                SET_ESP(esp, mask);
            }
            return;
        case 6:  /* 286 interrupt gate */
        case 7:  /* 286 trap gate */
        case 14: /* 386 interrupt gate */
        case 15: /* 386 trap gate */
            break;
        default:
            raise_exception_err(env, EXCP0D_GPF, intno * 8 + 2);
            break;
    }
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    /* check privilege if software int */
    if (is_int && dpl < cpl)
        raise_exception_err(env, EXCP0D_GPF, intno * 8 + 2);
    /* check valid bit */
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(env, EXCP0B_NOSEG, intno * 8 + 2);
    selector = e1 >> 16;
    offset = (e2 & 0xffff0000) | (e1 & 0x0000ffff);
    if ((selector & 0xfffc) == 0)
        raise_exception_err(env, EXCP0D_GPF, 0);

    if (load_segment(&e1, &e2, selector) != 0)
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_S_MASK) || !(e2 & (DESC_CS_MASK)))
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (dpl > cpl)
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(env, EXCP0B_NOSEG, selector & 0xfffc);
    if (!(e2 & DESC_C_MASK) && dpl < cpl) {
        /* to inner privilege */
        get_ss_esp_from_tss(env, &ss, &esp, dpl, GETPC());
        if ((ss & 0xfffc) == 0)
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        if ((ss & 3) != dpl)
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        if (load_segment(&ss_e1, &ss_e2, ss) != 0)
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        ss_dpl = (ss_e2 >> DESC_DPL_SHIFT) & 3;
        if (ss_dpl != dpl)
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        if (!(ss_e2 & DESC_S_MASK) || (ss_e2 & DESC_CS_MASK) || !(ss_e2 & DESC_W_MASK))
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        if (!(ss_e2 & DESC_P_MASK))
            raise_exception_err(env, EXCP0A_TSS, ss & 0xfffc);
        new_stack = 1;
        sp_mask = get_sp_mask(ss_e2);
        ssp = get_seg_base(ss_e1, ss_e2);
    } else if ((e2 & DESC_C_MASK) || dpl == cpl) {
        /* to same privilege */
        if (env->mflags & VM_MASK)
            raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0;
        sp_mask = get_sp_mask(env->segs[R_SS].flags);
        ssp = env->segs[R_SS].base;
        esp = ESP;
        dpl = cpl;
    } else {
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0; /* avoid warning */
        sp_mask = 0;   /* avoid warning */
        ssp = 0;       /* avoid warning */
        esp = 0;       /* avoid warning */
    }

    shift = type >> 3;

#if 0
    /* XXX: check that enough room is available */
    push_size = 6 + (new_stack << 2) + (has_error_code << 1);
    if (RR_cpu(env, eflags) & VM_MASK)
        push_size += 8;
    push_size <<= shift;
#endif
    if (shift == 1) {
        if (new_stack) {
            if (env->mflags & VM_MASK) {
                PUSHL(ssp, esp, sp_mask, env->segs[R_GS].selector);
                PUSHL(ssp, esp, sp_mask, env->segs[R_FS].selector);
                PUSHL(ssp, esp, sp_mask, env->segs[R_DS].selector);
                PUSHL(ssp, esp, sp_mask, env->segs[R_ES].selector);
            }
            PUSHL(ssp, esp, sp_mask, env->segs[R_SS].selector);
            PUSHL(ssp, esp, sp_mask, ESP);
        }
        PUSHL(ssp, esp, sp_mask, compute_eflags());
        PUSHL(ssp, esp, sp_mask, env->segs[R_CS].selector);
        PUSHL(ssp, esp, sp_mask, old_eip);
        if (has_error_code) {
            PUSHL(ssp, esp, sp_mask, error_code);
        }
    } else {
        if (new_stack) {
            if (env->mflags & VM_MASK) {
                PUSHW(ssp, esp, sp_mask, env->segs[R_GS].selector);
                PUSHW(ssp, esp, sp_mask, env->segs[R_FS].selector);
                PUSHW(ssp, esp, sp_mask, env->segs[R_DS].selector);
                PUSHW(ssp, esp, sp_mask, env->segs[R_ES].selector);
            }
            PUSHW(ssp, esp, sp_mask, env->segs[R_SS].selector);
            PUSHW(ssp, esp, sp_mask, ESP);
        }
        PUSHW(ssp, esp, sp_mask, compute_eflags());
        PUSHW(ssp, esp, sp_mask, env->segs[R_CS].selector);
        PUSHW(ssp, esp, sp_mask, old_eip);
        if (has_error_code) {
            PUSHW(ssp, esp, sp_mask, error_code);
        }
    }

    if (new_stack) {
        if (env->mflags & VM_MASK) {
            cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0, 0);
        }
        ss = (ss & ~3) | dpl;
        cpu_x86_load_seg_cache(env, R_SS, ss, ssp, get_seg_limit(ss_e1, ss_e2), ss_e2);
    }
    SET_ESP(esp, sp_mask);

    selector = (selector & ~3) | dpl;
    cpu_x86_load_seg_cache(env, R_CS, selector, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
    cpu_x86_set_cpl(env, dpl);
    env->eip = offset;
    WR_se_eip(env, offset);

    /* interrupt gate clear IF mask */
    if ((type & 1) == 0) {
        env->mflags &= ~IF_MASK;
    }
    env->mflags &= ~(TF_MASK | VM_MASK | RF_MASK | NT_MASK);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, dpl);
    }
#endif
}

#ifdef TARGET_X86_64

#define PUSHQ(sp, val)                  \
    {                                   \
        sp -= 8;                        \
        cpu_stq_kernel(env, sp, (val)); \
    }

#define POPQ(sp, val)                  \
    {                                  \
        val = cpu_ldq_kernel(env, sp); \
        sp += 8;                       \
    }

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
#define POPQ_S(mgr, sp, val)                  \
    {                                         \
        val = g_sqi.expr.read_mem_q(mgr, sp); \
        sp += 8;                              \
    }
#endif

static inline target_ulong get_rsp_from_tss(int level) {
    int index;

#if 0
    printf("TR: base=" TARGET_FMT_lx " limit=%x\n",
           env->tr.base, env->tr.limit);
#endif

    if (!(env->tr.flags & DESC_P_MASK))
        cpu_abort(env, "invalid tss");
    index = 8 * level + 4;
    if ((index + 7) > env->tr.limit)
        raise_exception_err(env, EXCP0A_TSS, env->tr.selector & 0xfffc);
    return cpu_ldq_kernel(env, env->tr.base + index);
}

/* 64 bit interrupt */
static void do_interrupt64(CPUX86State *env, int intno, int is_int, int error_code, target_ulong next_eip, int is_hw) {
    SegmentCache *dt;
    target_ulong ptr;
    int type, dpl, selector, cpl, ist;
    int has_error_code, new_stack;
    uint32_t e1, e2, e3, ss;
    target_ulong old_eip, esp, offset;

    has_error_code = 0;
    if (!is_int && !is_hw)
        has_error_code = exeption_has_error_code(intno);
    if (is_int)
        old_eip = next_eip;
    else
        old_eip = env->eip;

    dt = &env->idt;
    if (intno * 16 + 15 > dt->limit)
        raise_exception_err(env, EXCP0D_GPF, intno * 16 + 2);
    ptr = dt->base + intno * 16;
    e1 = cpu_ldl_kernel(env, ptr);
    e2 = cpu_ldl_kernel(env, ptr + 4);
    e3 = cpu_ldl_kernel(env, ptr + 8);
    /* check gate type */
    type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
    switch (type) {
        case 14: /* 386 interrupt gate */
        case 15: /* 386 trap gate */
            break;
        default:
            raise_exception_err(env, EXCP0D_GPF, intno * 16 + 2);
            break;
    }
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    /* check privilege if software int */
    if (is_int && dpl < cpl)
        raise_exception_err(env, EXCP0D_GPF, intno * 16 + 2);
    /* check valid bit */
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(env, EXCP0B_NOSEG, intno * 16 + 2);
    selector = e1 >> 16;
    offset = ((target_ulong) e3 << 32) | (e2 & 0xffff0000) | (e1 & 0x0000ffff);
    ist = e2 & 7;
    if ((selector & 0xfffc) == 0)
        raise_exception_err(env, EXCP0D_GPF, 0);

    if (load_segment(&e1, &e2, selector) != 0)
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_S_MASK) || !(e2 & (DESC_CS_MASK)))
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (dpl > cpl)
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(env, EXCP0B_NOSEG, selector & 0xfffc);
    if (!(e2 & DESC_L_MASK) || (e2 & DESC_B_MASK))
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    if ((!(e2 & DESC_C_MASK) && dpl < cpl) || ist != 0) {
        /* to inner privilege */
        if (ist != 0)
            esp = get_rsp_from_tss(ist + 3);
        else
            esp = get_rsp_from_tss(dpl);
        esp &= ~0xfLL; /* align stack */
        ss = 0;
        new_stack = 1;
    } else if ((e2 & DESC_C_MASK) || dpl == cpl) {
        /* to same privilege */
        if (env->mflags & VM_MASK)
            raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0;
        if (ist != 0)
            esp = get_rsp_from_tss(ist + 3);
        else
            esp = ESP;
        esp &= ~0xfLL; /* align stack */
        dpl = cpl;
    } else {
        raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0; /* avoid warning */
        esp = 0;       /* avoid warning */
    }

    PUSHQ(esp, env->segs[R_SS].selector);
    PUSHQ(esp, ESP);
    PUSHQ(esp, compute_eflags());
    PUSHQ(esp, env->segs[R_CS].selector);
    PUSHQ(esp, old_eip);
    if (has_error_code) {
        PUSHQ(esp, error_code);
    }

    if (new_stack) {
        ss = 0 | dpl;
        cpu_x86_load_seg_cache(env, R_SS, ss, 0, 0, 0);
    }
    ESP_W(esp);

    selector = (selector & ~3) | dpl;
    cpu_x86_load_seg_cache(env, R_CS, selector, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
    cpu_x86_set_cpl(env, dpl);
    env->eip = offset;
    WR_se_eip(env, offset);

    /* interrupt gate clear IF mask */
    if ((type & 1) == 0) {
        env->mflags &= ~IF_MASK;
    }
    env->mflags &= ~(TF_MASK | VM_MASK | RF_MASK | NT_MASK);
}
#endif

#ifdef TARGET_X86_64
void helper_syscall(int next_eip_addend) {
    int selector;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int old_cpl = env->hflags & HF_CPL_MASK;
#endif

    if (!(env->efer & MSR_EFER_SCE)) {
        raise_exception_err(env, EXCP06_ILLOP, 0);
    }
    selector = (env->star >> 32) & 0xffff;
    if (env->hflags & HF_LMA_MASK) {
        int code64;
        ECX_W(env->eip + next_eip_addend);
        WR_cpu(env, regs[11], compute_eflags());

        code64 = env->hflags & HF_CS64_MASK;

        cpu_x86_set_cpl(env, 0);
        cpu_x86_load_seg_cache(env, R_CS, selector & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK |
                                   DESC_L_MASK);
        cpu_x86_load_seg_cache(env, R_SS, (selector + 8) & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK);
        CC_SRC_W(helper_cc_compute_all(CC_OP) & ~env->fmask);
        CC_OP_W(CC_OP_EFLAGS);
        if (env->fmask & DF_MASK)
            DF_W(1); // this means df = 0, see CPUX86State.df in cpu.h
        env->mflags &= ~env->fmask;
        if (code64) {
            env->eip = env->lstar;
            WR_se_eip(env, env->lstar);
        } else {
            env->eip = env->cstar;
            WR_se_eip(env, env->cstar);
        }
    } else {
        ECX_W((uint32_t) (env->eip + next_eip_addend));

        cpu_x86_set_cpl(env, 0);
        cpu_x86_load_seg_cache(env, R_CS, selector & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
                                   DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_SS, (selector + 8) & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK);
        env->mflags &= ~(IF_MASK | RF_MASK | VM_MASK);
        env->eip = (uint32_t) env->star;
        WR_se_eip(env, (uint32_t) env->star);
    }

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(old_cpl, 0);
    }
#endif
}
#endif

#ifdef TARGET_X86_64
void helper_sysret(int dflag) {
    int cpl, selector;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int old_cpl = env->hflags & HF_CPL_MASK;
#endif

    if (!(env->efer & MSR_EFER_SCE)) {
        raise_exception_err(env, EXCP06_ILLOP, 0);
    }
    cpl = env->hflags & HF_CPL_MASK;
    if (!(env->cr[0] & CR0_PE_MASK) || cpl != 0) {
        raise_exception_err(env, EXCP0D_GPF, 0);
    }
    selector = (env->star >> 48) & 0xffff;
    if (env->hflags & HF_LMA_MASK) {
        if (dflag == 2) {
            cpu_x86_load_seg_cache(env, R_CS, (selector + 16) | 3, 0, 0xffffffff,
                                   DESC_G_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) | DESC_CS_MASK |
                                       DESC_R_MASK | DESC_A_MASK | DESC_L_MASK);
            WR_se_eip(env, ECX);
            env->eip = ECX;
        } else {
            cpu_x86_load_seg_cache(env, R_CS, selector | 3, 0, 0xffffffff,
                                   DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                       DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
            WR_se_eip(env, (uint32_t) ECX);
            env->eip = (uint32_t) ECX;
        }
        cpu_x86_load_seg_cache(env, R_SS, selector + 8, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_W_MASK | DESC_A_MASK);
        load_eflags((uint32_t) (RR_cpu(env, regs[11])),
                    TF_MASK | AC_MASK | ID_MASK | IF_MASK | IOPL_MASK | VM_MASK | RF_MASK | NT_MASK);
        cpu_x86_set_cpl(env, 3);
    } else {
        cpu_x86_load_seg_cache(env, R_CS, selector | 3, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
        WR_se_eip(env, (uint32_t) ECX);
        env->eip = (uint32_t) ECX;
        cpu_x86_load_seg_cache(env, R_SS, selector + 8, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_W_MASK | DESC_A_MASK);
        env->mflags |= IF_MASK;
        cpu_x86_set_cpl(env, 3);
    }

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(old_cpl, 3);
    }
#endif
}
#endif

/* real mode interrupt */
static void do_interrupt_real(CPUX86State *env, int intno, int is_int, int error_code, unsigned int next_eip) {
    SegmentCache *dt;
    target_ulong ptr, ssp;
    int selector;
    uint32_t offset, esp;
    uint32_t old_cs, old_eip;

    /* real mode (simpler !) */
    dt = &env->idt;
    if (intno * 4 + 3 > dt->limit)
        raise_exception_err(env, EXCP0D_GPF, intno * 8 + 2);
    ptr = dt->base + intno * 4;
    offset = cpu_lduw_kernel(env, ptr);
    selector = cpu_lduw_kernel(env, ptr + 2);
    esp = ESP;
    ssp = env->segs[R_SS].base;
    if (is_int)
        old_eip = next_eip;
    else
        old_eip = env->eip;
    old_cs = env->segs[R_CS].selector;
    /* XXX: use SS segment size ? */
    PUSHW(ssp, esp, 0xffff, compute_eflags());
    PUSHW(ssp, esp, 0xffff, old_cs);
    PUSHW(ssp, esp, 0xffff, old_eip);

    /* update processor state */
    ESP_W((ESP & ~0xffff) | (esp & 0xffff));
    WR_se_eip(env, offset);
    env->eip = offset;
    env->segs[R_CS].selector = selector;
    env->segs[R_CS].base = (selector << 4);
    env->mflags &= ~(IF_MASK | TF_MASK | AC_MASK | RF_MASK);
}

static void handle_even_inj(int intno, int is_int, int error_code, int is_hw, int rm) {
    uint32_t event_inj = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj));
    if (!(event_inj & SVM_EVTINJ_VALID)) {
        int type;
        if (is_int)
            type = SVM_EVTINJ_TYPE_SOFT;
        else
            type = SVM_EVTINJ_TYPE_EXEPT;
        event_inj = intno | type | SVM_EVTINJ_VALID;
        if (!rm && exeption_has_error_code(intno)) {
            event_inj |= SVM_EVTINJ_VALID_ERR;
            stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj_err), error_code);
        }
        stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj), event_inj);
    }
}

/*
 * Begin execution of an interruption. is_int is TRUE if coming from
 * the int instruction. next_eip is the EIP value AFTER the interrupt
 * instruction. It is only relevant if is_int is TRUE.
 */
#ifdef CONFIG_SYMBEX

// This function is implemented in the symbolic execution engines.
// It interecpts all the original calls to the interrupt handler routine.
static void do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw) {
    g_sqi.exec.do_interrupt_all(intno, is_int, error_code, next_eip, is_hw);
}

// This function will be called by the symbolic execution engine if running concretely
void se_do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw)
#else
static void do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw)
#endif
{
    if (libcpu_loglevel_mask(CPU_LOG_INT)) {
        if ((env->cr[0] & CR0_PE_MASK)) {
            static int count;
            libcpu_log("%6d: v=%02x e=%04x i=%d cpl=%d IP=%04x:" TARGET_FMT_lx " pc=" TARGET_FMT_lx
                       " SP=%04x:" TARGET_FMT_lx,
                       count, intno, error_code, is_int, env->hflags & HF_CPL_MASK, env->segs[R_CS].selector, EIP,
                       (int) env->segs[R_CS].base + EIP, env->segs[R_SS].selector, ESP);
            if (intno == 0x0e) {
                libcpu_log(" CR2=" TARGET_FMT_lx, env->cr[2]);
            } else {
                libcpu_log(" EAX=" TARGET_FMT_lx, EAX);
            }
            libcpu_log("\n");
#ifndef SYMBEX_LLVM_LIB
            log_cpu_state(env, X86_DUMP_CCOP);
#endif
#if 0
            {
                int i;
                target_ulong ptr;
                libcpu_log("       code=");
                ptr = env->segs[R_CS].base + env->eip;
                for(i = 0; i < 16; i++) {
                    libcpu_log(" %02x", ldub(ptr + i));
                }
                libcpu_log("\n");
            }
#endif
            count++;
        }
    }
    if (env->cr[0] & CR0_PE_MASK) {
        if (env->hflags & HF_SVMI_MASK)
            handle_even_inj(intno, is_int, error_code, is_hw, 0);
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            do_interrupt64(env, intno, is_int, error_code, next_eip, is_hw);
        } else
#endif
        {
            do_interrupt_protected(env, intno, is_int, error_code, next_eip, is_hw);
        }
    } else {
        if (env->hflags & HF_SVMI_MASK)
            handle_even_inj(intno, is_int, error_code, is_hw, 1);
        do_interrupt_real(env, intno, is_int, error_code, next_eip);
    }

    if (env->hflags & HF_SVMI_MASK) {
        uint32_t event_inj = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj));
        stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj), event_inj & ~SVM_EVTINJ_VALID);
    }
}

void do_interrupt(CPUX86State *env) {
    /* simulate a real cpu exception. On i386, it can
       trigger new exceptions, but we do not handle
       double or triple faults yet. */
    do_interrupt_all(env->exception_index, env->exception_is_int, env->error_code, env->exception_next_eip, 0);
    /* successfully delivered */
    env->old_exception = -1;
}

void do_interrupt_x86_hardirq(CPUX86State *env, int intno, int is_hw) {
    do_interrupt_all(intno, 0, 0, 0, is_hw);
}

/*
 * Check nested exceptions and change to double or triple fault if
 * needed. It should only be called, if this is not an interrupt.
 * Returns the new exception number.
 */
static int check_exception(int intno, int *error_code) {
    int first_contributory = env->old_exception == 0 || (env->old_exception >= 10 && env->old_exception <= 13);
    int second_contributory = intno == 0 || (intno >= 10 && intno <= 13);

    libcpu_log_mask(CPU_LOG_INT, "check_exception old: 0x%x new 0x%x\n", env->old_exception, intno);

    if (env->old_exception == EXCP08_DBLE) {
        if (env->hflags & HF_SVMI_MASK)
            helper_vmexit(SVM_EXIT_SHUTDOWN, 0); /* does not return */

        libcpu_log_mask(CPU_LOG_RESET, "Triple fault\n");

        // TODO: do a reboot
        exit(-1);
        return EXCP_HLT;
    }

    if ((first_contributory && second_contributory) ||
        (env->old_exception == EXCP0E_PAGE && (second_contributory || (intno == EXCP0E_PAGE)))) {
        intno = EXCP08_DBLE;
        *error_code = 0;
    }

    if (second_contributory || (intno == EXCP0E_PAGE) || (intno == EXCP08_DBLE))
        env->old_exception = intno;

    return intno;
}

/*
 * Signal an interruption. It is executed in the main CPU loop.
 * is_int is TRUE if coming from the int instruction. next_eip is the
 * EIP value AFTER the interrupt instruction. It is only relevant if
 * is_int is TRUE.
 */
static void LIBCPU_NORETURN raise_interrupt2(CPUX86State *env, int intno, int is_int, int error_code,
                                             int next_eip_addend, uintptr_t retaddr) {
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
    g_sqi.expr.mgr_clear();
#endif

    if (!is_int) {
        helper_svm_check_intercept_param(SVM_EXIT_EXCP_BASE + intno, error_code);
        intno = check_exception(intno, &error_code);
    } else {
        helper_svm_check_intercept_param(SVM_EXIT_SWINT, 0);
    }

    env->exception_index = intno;
    env->error_code = error_code;
    env->exception_is_int = is_int;
    env->exception_next_eip = env->eip + next_eip_addend;
    cpu_loop_exit_restore(env, retaddr);
}

/* shortcuts to generate exceptions */

void QEMU_NORETURN raise_interrupt(CPUX86State *env, int intno, int is_int, int error_code, int next_eip_addend) {
    raise_interrupt2(env, intno, is_int, error_code, next_eip_addend, 0);
}

void QEMU_NORETURN raise_exception_err(CPUX86State *env, int exception_index, int error_code) {
    raise_interrupt2(env, exception_index, 0, error_code, 0, 0);
}

void QEMU_NORETURN raise_exception_err_ra(CPUX86State *env, int exception_index, int error_code, uintptr_t retaddr) {
    raise_interrupt2(env, exception_index, 0, error_code, 0, retaddr);
}

void QEMU_NORETURN raise_exception(CPUX86State *env, int exception_index) {
    raise_interrupt2(env, exception_index, 0, 0, 0, 0);
}

void QEMU_NORETURN raise_exception_ra(CPUX86State *env, int exception_index, uintptr_t retaddr) {
    raise_interrupt2(env, exception_index, 0, 0, 0, retaddr);
}
/* SMM support */
#ifdef TARGET_X86_64
#define SMM_REVISION_ID 0x00020064
#else
#define SMM_REVISION_ID 0x00020000
#endif

static void cpu_smm_update(CPUX86State *env) {
    assert(0 && "Not implemented");
}

void do_smm_enter(CPUX86State *env1) {
    target_ulong sm_state;
    SegmentCache *dt;
    int i, offset;
    CPUX86State *saved_env;

    saved_env = env;
    env = env1;

    libcpu_log_mask(CPU_LOG_INT, "SMM: enter\n");
    log_cpu_state_mask(CPU_LOG_INT, env, X86_DUMP_CCOP);

    env->hflags |= HF_SMM_MASK;
    cpu_smm_update(env);

    sm_state = env->smbase + 0x8000;

#ifdef TARGET_X86_64
    for (i = 0; i < 6; i++) {
        dt = &env->segs[i];
        offset = 0x7e00 + i * 16;
        stw_phys(sm_state + offset, dt->selector);
        stw_phys(sm_state + offset + 2, (dt->flags >> 8) & 0xf0ff);
        stl_phys(sm_state + offset + 4, dt->limit);
        stq_phys(sm_state + offset + 8, dt->base);
    }

    stq_phys(sm_state + 0x7e68, env->gdt.base);
    stl_phys(sm_state + 0x7e64, env->gdt.limit);

    stw_phys(sm_state + 0x7e70, env->ldt.selector);
    stq_phys(sm_state + 0x7e78, env->ldt.base);
    stl_phys(sm_state + 0x7e74, env->ldt.limit);
    stw_phys(sm_state + 0x7e72, (env->ldt.flags >> 8) & 0xf0ff);

    stq_phys(sm_state + 0x7e88, env->idt.base);
    stl_phys(sm_state + 0x7e84, env->idt.limit);

    stw_phys(sm_state + 0x7e90, env->tr.selector);
    stq_phys(sm_state + 0x7e98, env->tr.base);
    stl_phys(sm_state + 0x7e94, env->tr.limit);
    stw_phys(sm_state + 0x7e92, (env->tr.flags >> 8) & 0xf0ff);

    stq_phys(sm_state + 0x7ed0, env->efer);

    stq_phys(sm_state + 0x7ff8, EAX);
    stq_phys(sm_state + 0x7ff0, ECX);
    stq_phys(sm_state + 0x7fe8, EDX);
    stq_phys(sm_state + 0x7fe0, EBX);
    stq_phys(sm_state + 0x7fd8, ESP);
    stq_phys(sm_state + 0x7fd0, EBP);
    stq_phys(sm_state + 0x7fc8, ESI);
    stq_phys(sm_state + 0x7fc0, EDI);
    for (i = 8; i < 16; i++)
        stq_phys(sm_state + 0x7ff8 - i * 8, RR_cpu(env, regs[i]));
    stq_phys(sm_state + 0x7f78, env->eip);
    stl_phys(sm_state + 0x7f70, compute_eflags());
    stl_phys(sm_state + 0x7f68, env->dr[6]);
    stl_phys(sm_state + 0x7f60, env->dr[7]);

    stl_phys(sm_state + 0x7f48, env->cr[4]);
    stl_phys(sm_state + 0x7f50, env->cr[3]);
    stl_phys(sm_state + 0x7f58, env->cr[0]);

    stl_phys(sm_state + 0x7efc, SMM_REVISION_ID);
    stl_phys(sm_state + 0x7f00, env->smbase);
#else
    stl_phys(sm_state + 0x7ffc, env->cr[0]);
    stl_phys(sm_state + 0x7ff8, env->cr[3]);
    stl_phys(sm_state + 0x7ff4, compute_eflags());
    stl_phys(sm_state + 0x7ff0, env->eip);
    stl_phys(sm_state + 0x7fec, EDI);
    stl_phys(sm_state + 0x7fe8, ESI);
    stl_phys(sm_state + 0x7fe4, EBP);
    stl_phys(sm_state + 0x7fe0, ESP);
    stl_phys(sm_state + 0x7fdc, EBX);
    stl_phys(sm_state + 0x7fd8, EDX);
    stl_phys(sm_state + 0x7fd4, ECX);
    stl_phys(sm_state + 0x7fd0, EAX);
    stl_phys(sm_state + 0x7fcc, env->dr[6]);
    stl_phys(sm_state + 0x7fc8, env->dr[7]);

    stl_phys(sm_state + 0x7fc4, env->tr.selector);
    stl_phys(sm_state + 0x7f64, env->tr.base);
    stl_phys(sm_state + 0x7f60, env->tr.limit);
    stl_phys(sm_state + 0x7f5c, (env->tr.flags >> 8) & 0xf0ff);

    stl_phys(sm_state + 0x7fc0, env->ldt.selector);
    stl_phys(sm_state + 0x7f80, env->ldt.base);
    stl_phys(sm_state + 0x7f7c, env->ldt.limit);
    stl_phys(sm_state + 0x7f78, (env->ldt.flags >> 8) & 0xf0ff);

    stl_phys(sm_state + 0x7f74, env->gdt.base);
    stl_phys(sm_state + 0x7f70, env->gdt.limit);

    stl_phys(sm_state + 0x7f58, env->idt.base);
    stl_phys(sm_state + 0x7f54, env->idt.limit);

    for (i = 0; i < 6; i++) {
        dt = &env->segs[i];
        if (i < 3)
            offset = 0x7f84 + i * 12;
        else
            offset = 0x7f2c + (i - 3) * 12;
        stl_phys(sm_state + 0x7fa8 + i * 4, dt->selector);
        stl_phys(sm_state + offset + 8, dt->base);
        stl_phys(sm_state + offset + 4, dt->limit);
        stl_phys(sm_state + offset, (dt->flags >> 8) & 0xf0ff);
    }
    stl_phys(sm_state + 0x7f14, env->cr[4]);

    stl_phys(sm_state + 0x7efc, SMM_REVISION_ID);
    stl_phys(sm_state + 0x7ef8, env->smbase);
#endif
    /* init SMM cpu state */

#ifdef TARGET_X86_64
    cpu_load_efer(env, 0);
#endif
    load_eflags(0, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    WR_se_eip(env, 0x00008000);
    env->eip = 0x00008000;
    cpu_x86_load_seg_cache(env, R_CS, (env->smbase >> 4) & 0xffff, env->smbase, 0xffffffff, 0);
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffffffff, 0);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffffffff, 0);
    cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffffffff, 0);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffffffff, 0);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffffffff, 0);

    cpu_x86_update_cr0(env, env->cr[0] & ~(CR0_PE_MASK | CR0_EM_MASK | CR0_TS_MASK | CR0_PG_MASK));
    cpu_x86_update_cr4(env, 0);
    env->dr[7] = 0x00000400;
    CC_OP_W(CC_OP_EFLAGS);
    env = saved_env;
}

void helper_rsm(void) {
    target_ulong sm_state;
    int i, offset;
    uint32_t val;

    sm_state = env->smbase + 0x8000;
#ifdef TARGET_X86_64
    cpu_load_efer(env, ldq_phys(sm_state + 0x7ed0));

    for (i = 0; i < 6; i++) {
        offset = 0x7e00 + i * 16;
        cpu_x86_load_seg_cache(env, i, lduw_phys(sm_state + offset), ldq_phys(sm_state + offset + 8),
                               ldl_phys(sm_state + offset + 4), (lduw_phys(sm_state + offset + 2) & 0xf0ff) << 8);
    }

    env->gdt.base = ldq_phys(sm_state + 0x7e68);
    env->gdt.limit = ldl_phys(sm_state + 0x7e64);

    env->ldt.selector = lduw_phys(sm_state + 0x7e70);
    env->ldt.base = ldq_phys(sm_state + 0x7e78);
    env->ldt.limit = ldl_phys(sm_state + 0x7e74);
    env->ldt.flags = (lduw_phys(sm_state + 0x7e72) & 0xf0ff) << 8;

    env->idt.base = ldq_phys(sm_state + 0x7e88);
    env->idt.limit = ldl_phys(sm_state + 0x7e84);

    env->tr.selector = lduw_phys(sm_state + 0x7e90);
    env->tr.base = ldq_phys(sm_state + 0x7e98);
    env->tr.limit = ldl_phys(sm_state + 0x7e94);
    env->tr.flags = (lduw_phys(sm_state + 0x7e92) & 0xf0ff) << 8;

    EAX_W(ldq_phys(sm_state + 0x7ff8));
    ECX_W(ldq_phys(sm_state + 0x7ff0));
    EDX_W(ldq_phys(sm_state + 0x7fe8));
    EBX_W(ldq_phys(sm_state + 0x7fe0));
    ESP_W(ldq_phys(sm_state + 0x7fd8));
    EBP_W(ldq_phys(sm_state + 0x7fd0));
    ESI_W(ldq_phys(sm_state + 0x7fc8));
    EDI_W(ldq_phys(sm_state + 0x7fc0));
    for (i = 8; i < 16; i++)
        WR_cpu(env, regs[i], ldq_phys(sm_state + 0x7ff8 - i * 8));

    env->eip = ldq_phys(sm_state + 0x7f78);
    WR_se_eip(env, env->eip);

    load_eflags(ldl_phys(sm_state + 0x7f70), ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    env->dr[6] = ldl_phys(sm_state + 0x7f68);
    env->dr[7] = ldl_phys(sm_state + 0x7f60);

    cpu_x86_update_cr4(env, ldl_phys(sm_state + 0x7f48));
    cpu_x86_update_cr3(env, ldl_phys(sm_state + 0x7f50));
    cpu_x86_update_cr0(env, ldl_phys(sm_state + 0x7f58));

    val = ldl_phys(sm_state + 0x7efc); /* revision ID */
    if (val & 0x20000) {
        env->smbase = ldl_phys(sm_state + 0x7f00) & ~0x7fff;
    }
#else
    cpu_x86_update_cr0(env, ldl_phys(sm_state + 0x7ffc));
    cpu_x86_update_cr3(env, ldl_phys(sm_state + 0x7ff8));
    load_eflags(ldl_phys(sm_state + 0x7ff4), ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    env->eip = ldl_phys(sm_state + 0x7ff0);
    WR_se_eip(env, env->eip);
    EDI_W(ldl_phys(sm_state + 0x7fec));
    ESI_W(ldl_phys(sm_state + 0x7fe8));
    EBP_W(ldl_phys(sm_state + 0x7fe4));
    ESP_W(ldl_phys(sm_state + 0x7fe0));
    EBX_W(ldl_phys(sm_state + 0x7fdc));
    EDX_W(ldl_phys(sm_state + 0x7fd8));
    ECX_W(ldl_phys(sm_state + 0x7fd4));
    EAX_W(ldl_phys(sm_state + 0x7fd0));
    env->dr[6] = ldl_phys(sm_state + 0x7fcc);
    env->dr[7] = ldl_phys(sm_state + 0x7fc8);

    env->tr.selector = ldl_phys(sm_state + 0x7fc4) & 0xffff;
    env->tr.base = ldl_phys(sm_state + 0x7f64);
    env->tr.limit = ldl_phys(sm_state + 0x7f60);
    env->tr.flags = (ldl_phys(sm_state + 0x7f5c) & 0xf0ff) << 8;

    env->ldt.selector = ldl_phys(sm_state + 0x7fc0) & 0xffff;
    env->ldt.base = ldl_phys(sm_state + 0x7f80);
    env->ldt.limit = ldl_phys(sm_state + 0x7f7c);
    env->ldt.flags = (ldl_phys(sm_state + 0x7f78) & 0xf0ff) << 8;

    env->gdt.base = ldl_phys(sm_state + 0x7f74);
    env->gdt.limit = ldl_phys(sm_state + 0x7f70);

    env->idt.base = ldl_phys(sm_state + 0x7f58);
    env->idt.limit = ldl_phys(sm_state + 0x7f54);

    for (i = 0; i < 6; i++) {
        if (i < 3)
            offset = 0x7f84 + i * 12;
        else
            offset = 0x7f2c + (i - 3) * 12;
        cpu_x86_load_seg_cache(env, i, ldl_phys(sm_state + 0x7fa8 + i * 4) & 0xffff, ldl_phys(sm_state + offset + 8),
                               ldl_phys(sm_state + offset + 4), (ldl_phys(sm_state + offset) & 0xf0ff) << 8);
    }
    cpu_x86_update_cr4(env, ldl_phys(sm_state + 0x7f14));

    val = ldl_phys(sm_state + 0x7efc); /* revision ID */
    if (val & 0x20000) {
        env->smbase = ldl_phys(sm_state + 0x7ef8) & ~0x7fff;
    }
#endif
    CC_OP_W(CC_OP_EFLAGS);
    env->hflags &= ~HF_SMM_MASK;
    cpu_smm_update(env);

    libcpu_log_mask(CPU_LOG_INT, "SMM: after RSM\n");
#ifndef SYMBEX_LLVM_LIB
    log_cpu_state_mask(CPU_LOG_INT, env, X86_DUMP_CCOP);
#endif
}

/* division, flags are undefined */

void helper_divb_AL(target_ulong t0) {
    unsigned int num, den, q, r;

    num = (EAX & 0xffff);
    den = (t0 & 0xff);
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q > 0xff)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    q &= 0xff;
    r = (num % den) & 0xff;
    EAX_W((EAX & ~0xffff) | (r << 8) | q);
}

void helper_idivb_AL(target_ulong t0) {
    int num, den, q, r;

    num = (int16_t) EAX;
    den = (int8_t) t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q != (int8_t) q)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    q &= 0xff;
    r = (num % den) & 0xff;
    EAX_W((EAX & ~0xffff) | (r << 8) | q);
}

void helper_divw_AX(target_ulong t0) {
    unsigned int num, den, q, r;

    num = (EAX & 0xffff) | ((EDX & 0xffff) << 16);
    den = (t0 & 0xffff);
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q > 0xffff)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    q &= 0xffff;
    r = (num % den) & 0xffff;
    EAX_W((EAX & ~0xffff) | q);
    EDX_W((EDX & ~0xffff) | r);
}

void helper_idivw_AX(target_ulong t0) {
    int num, den, q, r;

    num = (EAX & 0xffff) | ((EDX & 0xffff) << 16);
    den = (int16_t) t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    if (q != (int16_t) q)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    q &= 0xffff;
    r = (num % den) & 0xffff;
    EAX_W((EAX & ~0xffff) | q);
    EDX_W((EDX & ~0xffff) | r);
}

void helper_divl_EAX(target_ulong t0) {
    unsigned int den, r;
    uint64_t num, q;

    num = ((uint32_t) EAX) | ((uint64_t) ((uint32_t) EDX) << 32);
    den = t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    r = (num % den);
    if (q > 0xffffffff)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    EAX_W((uint32_t) q);
    EDX_W((uint32_t) r);
}

void helper_idivl_EAX(target_ulong t0) {
    int den, r;
    int64_t num, q;

    num = ((uint32_t) EAX) | ((uint64_t) ((uint32_t) EDX) << 32);
    den = t0;
    if (den == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    q = (num / den);
    r = (num % den);
    if (q != (int32_t) q)
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    EAX_W((uint32_t) q);
    EDX_W((uint32_t) r);
}

/* bcd */

/* XXX: exception */
void helper_aam(int base) {
    int al, ah;
    al = EAX & 0xff;
    ah = al / base;
    al = al % base;
    EAX_W((EAX & ~0xffff) | al | (ah << 8));
    CC_DST_W(al);
}

void helper_aad(int base) {
    int al, ah;
    al = EAX & 0xff;
    ah = (EAX >> 8) & 0xff;
    al = ((ah * base) + al) & 0xff;
    EAX_W((EAX & ~0xffff) | al);
    CC_DST_W(al);
}

void helper_aaa(void) {
    int icarry;
    int al, ah, af;
    int eflags;

    eflags = helper_cc_compute_all(CC_OP);
    af = eflags & CC_A;
    al = EAX & 0xff;
    ah = (EAX >> 8) & 0xff;

    icarry = (al > 0xf9);
    if (((al & 0x0f) > 9) || af) {
        al = (al + 6) & 0x0f;
        ah = (ah + 1 + icarry) & 0xff;
        eflags |= CC_C | CC_A;
    } else {
        eflags &= ~(CC_C | CC_A);
        al &= 0x0f;
    }
    EAX_W((EAX & ~0xffff) | al | (ah << 8));
    CC_SRC_W(eflags);
}

void helper_aas(void) {
    int icarry;
    int al, ah, af;
    int eflags;

    eflags = helper_cc_compute_all(CC_OP);
    af = eflags & CC_A;
    al = EAX & 0xff;
    ah = (EAX >> 8) & 0xff;

    icarry = (al < 6);
    if (((al & 0x0f) > 9) || af) {
        al = (al - 6) & 0x0f;
        ah = (ah - 1 - icarry) & 0xff;
        eflags |= CC_C | CC_A;
    } else {
        eflags &= ~(CC_C | CC_A);
        al &= 0x0f;
    }
    EAX_W((EAX & ~0xffff) | al | (ah << 8));
    CC_SRC_W(eflags);
}

void helper_daa(void) {
    int old_al, al, af, cf;
    int eflags;

    eflags = helper_cc_compute_all(CC_OP);
    cf = eflags & CC_C;
    af = eflags & CC_A;
    old_al = al = EAX & 0xff;

    eflags = 0;
    if (((al & 0x0f) > 9) || af) {
        al = (al + 6) & 0xff;
        eflags |= CC_A;
    }
    if ((old_al > 0x99) || cf) {
        al = (al + 0x60) & 0xff;
        eflags |= CC_C;
    }
    EAX_W((EAX & ~0xff) | al);
    /* well, speed is not an issue here, so we compute the flags by hand */
    eflags |= (al == 0) << 6;   /* zf */
    eflags |= parity_table[al]; /* pf */
    eflags |= (al & 0x80);      /* sf */
    CC_SRC_W(eflags);
}

void helper_das(void) {
    int al, al1, af, cf;
    int eflags;

    eflags = helper_cc_compute_all(CC_OP);
    cf = eflags & CC_C;
    af = eflags & CC_A;
    al = EAX & 0xff;

    eflags = 0;
    al1 = al;
    if (((al & 0x0f) > 9) || af) {
        eflags |= CC_A;
        if (al < 6 || cf)
            eflags |= CC_C;
        al = (al - 6) & 0xff;
    }
    if ((al1 > 0x99) || cf) {
        al = (al - 0x60) & 0xff;
        eflags |= CC_C;
    }
    EAX_W((EAX & ~0xff) | al);
    /* well, speed is not an issue here, so we compute the flags by hand */
    eflags |= (al == 0) << 6;   /* zf */
    eflags |= parity_table[al]; /* pf */
    eflags |= (al & 0x80);      /* sf */
    CC_SRC_W(eflags);
}

void helper_into(int next_eip_addend) {
    int eflags;
    eflags = helper_cc_compute_all(CC_OP);
    if (eflags & CC_O) {
        raise_interrupt(env, EXCP04_INTO, 1, 0, next_eip_addend);
    }
}

void helper_cmpxchg8b(target_ulong a0) {
    uint64_t d;
    int eflags;

    eflags = helper_cc_compute_all(CC_OP);
    d = ldq(a0);
    if (d == (((uint64_t) EDX << 32) | (uint32_t) EAX)) {
        stq(a0, ((uint64_t) ECX << 32) | (uint32_t) EBX);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        stq(a0, d);
        EDX_W((uint32_t) (d >> 32));
        EAX_W((uint32_t) d);
        eflags &= ~CC_Z;
    }
    CC_SRC_W(eflags);
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b(target_ulong a0) {
    uint64_t d0, d1;
    int eflags;

    if ((a0 & 0xf) != 0)
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    eflags = helper_cc_compute_all(CC_OP);
    d0 = ldq(a0);
    d1 = ldq(a0 + 8);
    if (d0 == EAX && d1 == EDX) {
        stq(a0, EBX);
        stq(a0 + 8, ECX);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        stq(a0, d0);
        stq(a0 + 8, d1);
        EDX_W(d1);
        EAX_W(d0);
        eflags &= ~CC_Z;
    }
    CC_SRC_W(eflags);
}
#endif

void helper_single_step(void) {
    check_hw_breakpoints(env, 1);
    env->dr[6] |= DR6_BS;
    raise_exception(env, EXCP01_DB);
}

void helper_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;

    helper_svm_check_intercept_param(SVM_EXIT_CPUID, 0);

    uint32_t index = (uint32_t) EAX;

    // XXX: workaround to avoid passing symbolic count information
    if (index == 4) {
        cpu_x86_cpuid(&env->cpuid, (uint32_t) EAX, (uint32_t) ECX, &eax, &ebx, &ecx, &edx);
    } else {
        cpu_x86_cpuid(&env->cpuid, (uint32_t) EAX, 0, &eax, &ebx, &ecx, &edx);
    }
    EAX_W(eax);
    EBX_W(ebx);
    ECX_W(ecx);
    EDX_W(edx);
}

void helper_enter_level(int level, int data32, target_ulong t1) {
    target_ulong ssp;
    uint32_t esp_mask, esp, ebp;

    esp_mask = get_sp_mask(env->segs[R_SS].flags);
    ssp = env->segs[R_SS].base;
    ebp = EBP;
    esp = ESP;
    if (data32) {
        /* 32 bit */
        esp -= 4;
        while (--level) {
            esp -= 4;
            ebp -= 4;
            stl(ssp + (esp & esp_mask), ldl(ssp + (ebp & esp_mask)));
        }
        esp -= 4;
        stl(ssp + (esp & esp_mask), t1);
    } else {
        /* 16 bit */
        esp -= 2;
        while (--level) {
            esp -= 2;
            ebp -= 2;
            stw(ssp + (esp & esp_mask), lduw(ssp + (ebp & esp_mask)));
        }
        esp -= 2;
        stw(ssp + (esp & esp_mask), t1);
    }
}

#ifdef TARGET_X86_64
void helper_enter64_level(int level, int data64, target_ulong t1) {
    target_ulong esp, ebp;
    ebp = EBP;
    esp = ESP;

    if (data64) {
        /* 64 bit */
        esp -= 8;
        while (--level) {
            esp -= 8;
            ebp -= 8;
            stq(esp, ldq(ebp));
        }
        esp -= 8;
        stq(esp, t1);
    } else {
        /* 16 bit */
        esp -= 2;
        while (--level) {
            esp -= 2;
            ebp -= 2;
            stw(esp, lduw(ebp));
        }
        esp -= 2;
        stw(esp, t1);
    }
}
#endif

void helper_lldt(int selector) {
    SegmentCache *dt;
    uint32_t e1, e2;
    int index, entry_limit;
    target_ulong ptr;

    selector &= 0xffff;
    if ((selector & 0xfffc) == 0) {
        /* XXX: NULL selector case: invalid LDT */
        env->ldt.base = 0;
        env->ldt.limit = 0;
    } else {
        if (selector & 0x4)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        dt = &env->gdt;
        index = selector & ~7;
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK)
            entry_limit = 15;
        else
#endif
            entry_limit = 7;
        if ((index + entry_limit) > dt->limit)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel(env, ptr);
        e2 = cpu_ldl_kernel(env, ptr + 4);
        if ((e2 & DESC_S_MASK) || ((e2 >> DESC_TYPE_SHIFT) & 0xf) != 2)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, GETPC());
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            uint32_t e3;
            e3 = cpu_ldl_kernel(env, ptr + 8);
            load_seg_cache_raw_dt(&env->ldt, e1, e2);
            env->ldt.base |= (target_ulong) e3 << 32;
        } else
#endif
        {
            load_seg_cache_raw_dt(&env->ldt, e1, e2);
        }
    }
    env->ldt.selector = selector;
}

void helper_ltr(int selector) {
    SegmentCache *dt;
    uint32_t e1, e2;
    int index, type, entry_limit;
    target_ulong ptr;

    selector &= 0xffff;
    if ((selector & 0xfffc) == 0) {
        /* NULL selector case: invalid TR */
        env->tr.base = 0;
        env->tr.limit = 0;
        env->tr.flags = 0;
    } else {
        if (selector & 0x4)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        dt = &env->gdt;
        index = selector & ~7;
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK)
            entry_limit = 15;
        else
#endif
            entry_limit = 7;
        if ((index + entry_limit) > dt->limit)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel(env, ptr);
        e2 = cpu_ldl_kernel(env, ptr + 4);
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        if ((e2 & DESC_S_MASK) || (type != 1 && type != 9))
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, GETPC());
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            uint32_t e3, e4;
            e3 = cpu_ldl_kernel(env, ptr + 8);
            e4 = cpu_ldl_kernel(env, ptr + 12);
            if ((e4 >> DESC_TYPE_SHIFT) & 0xf)
                raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
            load_seg_cache_raw_dt(&env->tr, e1, e2);
            env->tr.base |= (target_ulong) e3 << 32;
        } else
#endif
        {
            load_seg_cache_raw_dt(&env->tr, e1, e2);
        }
        e2 |= DESC_TSS_BUSY_MASK;
        cpu_stl_kernel(env, ptr + 4, e2);
    }
    env->tr.selector = selector;
}

/* only works if protected mode and not VM86. seg_reg must be != R_CS */
void helper_load_seg(int seg_reg, int selector) {
    uint32_t e1, e2;
    int cpl, dpl, rpl;
    SegmentCache *dt;
    int index;
    target_ulong ptr;

    selector &= 0xffff;
    cpl = env->hflags & HF_CPL_MASK;
    if ((selector & 0xfffc) == 0) {
        /* null selector case */
        if (seg_reg == R_SS
#ifdef TARGET_X86_64
            && (!(env->hflags & HF_CS64_MASK) || cpl == 3)
#endif
        )
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        cpu_x86_load_seg_cache(env, seg_reg, selector, 0, 0, 0);
    } else {

        if (selector & 0x4)
            dt = &env->ldt;
        else
            dt = &env->gdt;
        index = selector & ~7;
        if ((index + 7) > dt->limit)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel(env, ptr);
        e2 = cpu_ldl_kernel(env, ptr + 4);

        if (!(e2 & DESC_S_MASK))
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        rpl = selector & 3;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (seg_reg == R_SS) {
            /* must be writable segment */
            if ((e2 & DESC_CS_MASK) || !(e2 & DESC_W_MASK))
                raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
            if (rpl != cpl || dpl != cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        } else {
            /* must be readable segment */
            if ((e2 & (DESC_CS_MASK | DESC_R_MASK)) == DESC_CS_MASK)
                raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());

            if (!(e2 & DESC_CS_MASK) || !(e2 & DESC_C_MASK)) {
                /* if not conforming code, test rights */
                if (dpl < cpl || dpl < rpl)
                    raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
            }
        }

        if (!(e2 & DESC_P_MASK)) {
            if (seg_reg == R_SS)
                raise_exception_err_ra(env, EXCP0C_STACK, selector & 0xfffc, GETPC());
            else
                raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, GETPC());
        }

        /* set the access bit if not already set */
        if (!(e2 & DESC_A_MASK)) {
            e2 |= DESC_A_MASK;
            cpu_stl_kernel(env, ptr + 4, e2);
        }

        cpu_x86_load_seg_cache(env, seg_reg, selector, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
#if 0
        libcpu_log("load_seg: sel=0x%04x base=0x%08lx limit=0x%08lx flags=%08x\n",
                selector, (unsigned long)sc->base, sc->limit, sc->flags);
#endif
    }
}

/* protected mode jump */
void helper_ljmp_protected(int new_cs, target_ulong new_eip, int next_eip_addend) {
    int gate_cs, type;
    uint32_t e1, e2, cpl, dpl, rpl, limit;
    target_ulong next_eip;

    if ((new_cs & 0xfffc) == 0)
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    if (load_segment(&e1, &e2, new_cs) != 0)
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_S_MASK) {
        if (!(e2 & DESC_CS_MASK))
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (e2 & DESC_C_MASK) {
            /* conforming code segment */
            if (dpl > cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        } else {
            /* non conforming code segment */
            rpl = new_cs & 3;
            if (rpl > cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            if (dpl != cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        }
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());
        limit = get_seg_limit(e1, e2);
        if (new_eip > limit && !(env->hflags & HF_LMA_MASK) && !(e2 & DESC_L_MASK))
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        cpu_x86_load_seg_cache(env, R_CS, (new_cs & 0xfffc) | cpl, get_seg_base(e1, e2), limit, e2);
        EIP = new_eip;
        WR_se_eip(env, new_eip);
    } else {
        /* jump to call or task gate */
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        rpl = new_cs & 3;
        cpl = env->hflags & HF_CPL_MASK;
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        switch (type) {
            case 1: /* 286 TSS */
            case 9: /* 386 TSS */
            case 5: /* task gate */
                if (dpl < cpl || dpl < rpl)
                    raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
                next_eip = env->eip + next_eip_addend;
                switch_tss(env, new_cs, e1, e2, SWITCH_TSS_JMP, next_eip, GETPC());
                CC_OP_W(CC_OP_EFLAGS);
                break;
            case 4:  /* 286 call gate */
            case 12: /* 386 call gate */
                if ((dpl < cpl) || (dpl < rpl))
                    raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
                if (!(e2 & DESC_P_MASK))
                    raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());
                gate_cs = e1 >> 16;
                new_eip = (e1 & 0xffff);
                if (type == 12)
                    new_eip |= (e2 & 0xffff0000);
                if (load_segment(&e1, &e2, gate_cs) != 0)
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                dpl = (e2 >> DESC_DPL_SHIFT) & 3;
                /* must be code segment */
                if (((e2 & (DESC_S_MASK | DESC_CS_MASK)) != (DESC_S_MASK | DESC_CS_MASK)))
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                if (((e2 & DESC_C_MASK) && (dpl > cpl)) || (!(e2 & DESC_C_MASK) && (dpl != cpl)))
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                if (!(e2 & DESC_P_MASK))
                    raise_exception_err_ra(env, EXCP0D_GPF, gate_cs & 0xfffc, GETPC());
                limit = get_seg_limit(e1, e2);
                if (new_eip > limit)
                    raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
                cpu_x86_load_seg_cache(env, R_CS, (gate_cs & 0xfffc) | cpl, get_seg_base(e1, e2), limit, e2);
                EIP = new_eip;
                WR_se_eip(env, new_eip);
                break;
            default:
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
                break;
        }
    }
}

/* real mode call */
void helper_lcall_real(int new_cs, target_ulong new_eip1, int shift, int next_eip) {
    int new_eip;
    uint32_t esp, esp_mask;
    target_ulong ssp;

    new_eip = new_eip1;
    esp = ESP;
    esp_mask = get_sp_mask(env->segs[R_SS].flags);
    ssp = env->segs[R_SS].base;
    if (shift) {
        PUSHL(ssp, esp, esp_mask, env->segs[R_CS].selector);
        PUSHL(ssp, esp, esp_mask, next_eip);
    } else {
        PUSHW(ssp, esp, esp_mask, env->segs[R_CS].selector);
        PUSHW(ssp, esp, esp_mask, next_eip);
    }

    SET_ESP(esp, esp_mask);
    env->eip = new_eip;
    WR_se_eip(env, new_eip);
    env->segs[R_CS].selector = new_cs;
    env->segs[R_CS].base = (new_cs << 4);
}

/* protected mode call */
void helper_lcall_protected(int new_cs, target_ulong new_eip, int shift, int next_eip_addend) {
    int new_stack, i;
    uint32_t e1, e2, cpl, dpl, rpl, selector, offset, param_count;
    uint32_t ss = 0, ss_e1 = 0, ss_e2 = 0, sp, type, ss_dpl, sp_mask;
    uint32_t val, limit, old_sp_mask;
    target_ulong ssp, old_ssp, next_eip;

    next_eip = env->eip + next_eip_addend;
    LOG_PCALL("lcall %04x:%08x s=%d\n", new_cs, (uint32_t) new_eip, shift);
#ifndef SYMBEX_LLVM_LIB
    LOG_PCALL_STATE(env);
#endif
    if ((new_cs & 0xfffc) == 0)
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    if (load_segment(&e1, &e2, new_cs) != 0)
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
    cpl = env->hflags & HF_CPL_MASK;
    LOG_PCALL("desc=%08x:%08x\n", e1, e2);
    if (e2 & DESC_S_MASK) {
        if (!(e2 & DESC_CS_MASK))
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (e2 & DESC_C_MASK) {
            /* conforming code segment */
            if (dpl > cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        } else {
            /* non conforming code segment */
            rpl = new_cs & 3;
            if (rpl > cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            if (dpl != cpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        }
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());

#ifdef TARGET_X86_64
        /* XXX: check 16/32 bit cases in long mode */
        if (shift == 2) {
            target_ulong rsp;
            /* 64 bit case */
            rsp = ESP;
            PUSHQ(rsp, env->segs[R_CS].selector);
            PUSHQ(rsp, next_eip);
            /* from this point, not restartable */
            ESP_W(rsp);
            cpu_x86_load_seg_cache(env, R_CS, (new_cs & 0xfffc) | cpl, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
            EIP = new_eip;
            WR_se_eip(env, new_eip);
        } else
#endif
        {
            sp = ESP;
            sp_mask = get_sp_mask(env->segs[R_SS].flags);
            ssp = env->segs[R_SS].base;
            if (shift) {
                PUSHL(ssp, sp, sp_mask, env->segs[R_CS].selector);
                PUSHL(ssp, sp, sp_mask, next_eip);
            } else {
                PUSHW(ssp, sp, sp_mask, env->segs[R_CS].selector);
                PUSHW(ssp, sp, sp_mask, next_eip);
            }

            limit = get_seg_limit(e1, e2);
            if (new_eip > limit)
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
            /* from this point, not restartable */
            SET_ESP(sp, sp_mask);
            cpu_x86_load_seg_cache(env, R_CS, (new_cs & 0xfffc) | cpl, get_seg_base(e1, e2), limit, e2);
            EIP = new_eip;
            WR_se_eip(env, new_eip);
        }
    } else {
        /* check gate type */
        type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        rpl = new_cs & 3;
        switch (type) {
            case 1: /* available 286 TSS */
            case 9: /* available 386 TSS */
            case 5: /* task gate */
                if (dpl < cpl || dpl < rpl)
                    raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
                switch_tss(env, new_cs, e1, e2, SWITCH_TSS_CALL, next_eip, GETPC());
                CC_OP_W(CC_OP_EFLAGS);
                return;
            case 4:  /* 286 call gate */
            case 12: /* 386 call gate */
                break;
            default:
                raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
                break;
        }
        shift = type >> 3;

        if (dpl < cpl || dpl < rpl)
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, GETPC());
        /* check valid bit */
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, GETPC());
        selector = e1 >> 16;
        offset = (e2 & 0xffff0000) | (e1 & 0x0000ffff);
        param_count = e2 & 0x1f;
        if ((selector & 0xfffc) == 0)
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());

        if (load_segment(&e1, &e2, selector) != 0)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        if (!(e2 & DESC_S_MASK) || !(e2 & (DESC_CS_MASK)))
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (dpl > cpl)
            raise_exception_err_ra(env, EXCP0D_GPF, selector & 0xfffc, GETPC());
        if (!(e2 & DESC_P_MASK))
            raise_exception_err_ra(env, EXCP0B_NOSEG, selector & 0xfffc, GETPC());

        if (!(e2 & DESC_C_MASK) && dpl < cpl) {
            /* to inner privilege */
            get_ss_esp_from_tss(env, &ss, &sp, dpl, GETPC());
            LOG_PCALL("new ss:esp=%04x:%08x param_count=%d ESP=" TARGET_FMT_lx "\n", ss, sp, param_count, ESP);
            if ((ss & 0xfffc) == 0)
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());
            if ((ss & 3) != dpl)
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());
            if (load_segment(&ss_e1, &ss_e2, ss) != 0)
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());
            ss_dpl = (ss_e2 >> DESC_DPL_SHIFT) & 3;
            if (ss_dpl != dpl)
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());
            if (!(ss_e2 & DESC_S_MASK) || (ss_e2 & DESC_CS_MASK) || !(ss_e2 & DESC_W_MASK))
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());
            if (!(ss_e2 & DESC_P_MASK))
                raise_exception_err_ra(env, EXCP0A_TSS, ss & 0xfffc, GETPC());

            //            push_size = ((param_count * 2) + 8) << shift;

            old_sp_mask = get_sp_mask(env->segs[R_SS].flags);
            old_ssp = env->segs[R_SS].base;

            sp_mask = get_sp_mask(ss_e2);
            ssp = get_seg_base(ss_e1, ss_e2);
            if (shift) {
                PUSHL(ssp, sp, sp_mask, env->segs[R_SS].selector);
                PUSHL(ssp, sp, sp_mask, ESP);
                for (i = param_count - 1; i >= 0; i--) {
                    val = cpu_ldl_kernel(env, old_ssp + ((ESP + i * 4) & old_sp_mask));
                    PUSHL(ssp, sp, sp_mask, val);
                }
            } else {
                PUSHW(ssp, sp, sp_mask, env->segs[R_SS].selector);
                PUSHW(ssp, sp, sp_mask, ESP);
                for (i = param_count - 1; i >= 0; i--) {
                    val = cpu_lduw_kernel(env, old_ssp + ((ESP + i * 2) & old_sp_mask));
                    PUSHW(ssp, sp, sp_mask, val);
                }
            }
            new_stack = 1;
        } else {
            /* to same privilege */
            sp = ESP;
            sp_mask = get_sp_mask(env->segs[R_SS].flags);
            ssp = env->segs[R_SS].base;
            //            push_size = (4 << shift);
            new_stack = 0;
        }

        if (shift) {
            PUSHL(ssp, sp, sp_mask, env->segs[R_CS].selector);
            PUSHL(ssp, sp, sp_mask, next_eip);
        } else {
            PUSHW(ssp, sp, sp_mask, env->segs[R_CS].selector);
            PUSHW(ssp, sp, sp_mask, next_eip);
        }

        /* from this point, not restartable */

        if (new_stack) {
            ss = (ss & ~3) | dpl;
            cpu_x86_load_seg_cache(env, R_SS, ss, ssp, get_seg_limit(ss_e1, ss_e2), ss_e2);
        }

        selector = (selector & ~3) | dpl;
        cpu_x86_load_seg_cache(env, R_CS, selector, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
        cpu_x86_set_cpl(env, dpl);
        SET_ESP(sp, sp_mask);
        EIP = offset;
        WR_se_eip(env, offset);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
        if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
            g_sqi.events.on_privilege_change(cpl, dpl);
        }
#endif
    }
}

/* real and vm86 mode iret */
void helper_iret_real(int shift) {
    uint32_t sp, new_cs, new_eip, new_eflags, sp_mask;
    target_ulong ssp;
    int eflags_mask;

    sp_mask = 0xffff; /* XXXX: use SS segment size ? */
    sp = ESP;
    ssp = env->segs[R_SS].base;
    if (shift == 1) {
        /* 32 bits */
        POPL(ssp, sp, sp_mask, new_eip);
        POPL(ssp, sp, sp_mask, new_cs);
        new_cs &= 0xffff;
        POPL(ssp, sp, sp_mask, new_eflags);
    } else {
        /* 16 bits */
        POPW(ssp, sp, sp_mask, new_eip);
        POPW(ssp, sp, sp_mask, new_cs);
        POPW(ssp, sp, sp_mask, new_eflags);
    }
    ESP_W((ESP & ~sp_mask) | (sp & sp_mask));
    env->segs[R_CS].selector = new_cs;
    env->segs[R_CS].base = (new_cs << 4);

    env->eip = new_eip;
    WR_se_eip(env, new_eip);
    if (env->mflags & VM_MASK)
        eflags_mask = TF_MASK | AC_MASK | ID_MASK | IF_MASK | RF_MASK | NT_MASK;
    else
        eflags_mask = TF_MASK | AC_MASK | ID_MASK | IF_MASK | IOPL_MASK | RF_MASK | NT_MASK;
    if (shift == 0)
        eflags_mask &= 0xffff;
    load_eflags(new_eflags, eflags_mask);
    env->hflags2 &= ~HF2_NMI_MASK;
}

static inline void validate_seg(int seg_reg, int cpl) {
    int dpl;
    uint32_t e2;

    /* XXX: on x86_64, we do not want to nullify FS and GS because
       they may still contain a valid base. I would be interested to
       know how a real x86_64 CPU behaves */
    if ((seg_reg == R_FS || seg_reg == R_GS) && (env->segs[seg_reg].selector & 0xfffc) == 0)
        return;

    e2 = env->segs[seg_reg].flags;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (!(e2 & DESC_CS_MASK) || !(e2 & DESC_C_MASK)) {
        /* data or non conforming code segment */
        if (dpl < cpl) {
            cpu_x86_load_seg_cache(env, seg_reg, 0, 0, 0, 0);
        }
    }
}

/* protected mode iret */
static inline void helper_ret_protected(CPUX86State *env, int shift, int is_iret, int addend, uintptr_t ra) {
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
    void *mgr = NULL;
    void *symb_new_eflags = NULL;
#endif
    uint32_t new_cs, new_eflags, new_ss;
    uint32_t new_es, new_ds, new_fs, new_gs;
    uint32_t e1, e2, ss_e1, ss_e2;
    int cpl, dpl, rpl, eflags_mask, iopl;
    target_ulong ssp, sp, new_eip, new_esp, sp_mask;

    cpl = env->hflags & HF_CPL_MASK;

#ifdef TARGET_X86_64
    if (shift == 2)
        sp_mask = -1;
    else
#endif
        sp_mask = get_sp_mask(env->segs[R_SS].flags);
    sp = ESP;
    ssp = env->segs[R_SS].base;
    new_eflags = 0; /* avoid warning */
#ifdef TARGET_X86_64
    if (shift == 2) {
        POPQ(sp, new_eip);
        POPQ(sp, new_cs);
        new_cs &= 0xffff;
        if (is_iret) {
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
            mgr = g_sqi.expr.mgr();
            POPQ_S(mgr, sp, symb_new_eflags);
#else
            POPQ(sp, new_eflags);
#endif
        }
    } else
#endif
        if (shift == 1) {
        /* 32 bits */
        POPL_T(ssp, sp, sp_mask, new_eip);
        POPL_T(ssp, sp, sp_mask, new_cs);
        new_cs &= 0xffff;
        if (is_iret) {
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
            mgr = g_sqi.expr.mgr();
            POPL_T_S(mgr, ssp, sp, sp_mask, symb_new_eflags);
            if (g_sqi.expr.to_constant(g_sqi.expr.andc(mgr, symb_new_eflags, VM_MASK)))
                goto return_to_vm86;
#else
            POPL_T(ssp, sp, sp_mask, new_eflags);
            if (new_eflags & VM_MASK)
                goto return_to_vm86;
#endif
        }
    } else {
        /* 16 bits */
        POPW_T(ssp, sp, sp_mask, new_eip);
        POPW_T(ssp, sp, sp_mask, new_cs);
        if (is_iret)
            POPW_T(ssp, sp, sp_mask, new_eflags);
    }
    LOG_PCALL("lret new %04x:" TARGET_FMT_lx " s=%d addend=0x%x\n", new_cs, new_eip, shift, addend);
#ifndef SYMBEX_LLVM_LIB
    LOG_PCALL_STATE(env);
#endif
    if ((new_cs & 0xfffc) == 0)
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    if (load_segment(&e1, &e2, new_cs) != 0)
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    if (!(e2 & DESC_S_MASK) || !(e2 & DESC_CS_MASK))
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    rpl = new_cs & 3;
    if (rpl < cpl)
        raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (e2 & DESC_C_MASK) {
        if (dpl > rpl)
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    } else {
        if (dpl != rpl)
            raise_exception_err_ra(env, EXCP0D_GPF, new_cs & 0xfffc, ra);
    }
    if (!(e2 & DESC_P_MASK))
        raise_exception_err_ra(env, EXCP0B_NOSEG, new_cs & 0xfffc, ra);

    sp += addend;
    if (rpl == cpl && (!(env->hflags & HF_CS64_MASK) || ((env->hflags & HF_CS64_MASK) && !is_iret))) {
        /* return to same privilege level */
        cpu_x86_load_seg_cache(env, R_CS, new_cs, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
    } else {
/* return to different privilege level */
#ifdef TARGET_X86_64
        if (shift == 2) {
            POPQ(sp, new_esp);
            POPQ(sp, new_ss);
            new_ss &= 0xffff;
        } else
#endif
            if (shift == 1) {
            /* 32 bits */
            POPL_T(ssp, sp, sp_mask, new_esp);
            POPL_T(ssp, sp, sp_mask, new_ss);
            new_ss &= 0xffff;
        } else {
            /* 16 bits */
            POPW_T(ssp, sp, sp_mask, new_esp);
            POPW_T(ssp, sp, sp_mask, new_ss);
        }
        LOG_PCALL("new ss:esp=%04x:" TARGET_FMT_lx "\n", new_ss, new_esp);
        if ((new_ss & 0xfffc) == 0) {
#ifdef TARGET_X86_64
            /* NULL ss is allowed in long mode if cpl != 3*/
            /* XXX: test CS64 ? */
            if ((env->hflags & HF_LMA_MASK) && rpl != 3) {
                cpu_x86_load_seg_cache(env, R_SS, new_ss, 0, 0xffffffff,
                                       DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (rpl << DESC_DPL_SHIFT) |
                                           DESC_W_MASK | DESC_A_MASK);
                ss_e2 = DESC_B_MASK; /* XXX: should not be needed ? */
            } else
#endif
            {
                raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
            }
        } else {
            if ((new_ss & 3) != rpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_ss & 0xfffc, ra);
            if (load_segment(&ss_e1, &ss_e2, new_ss) != 0)
                raise_exception_err_ra(env, EXCP0D_GPF, new_ss & 0xfffc, ra);
            if (!(ss_e2 & DESC_S_MASK) || (ss_e2 & DESC_CS_MASK) || !(ss_e2 & DESC_W_MASK))
                raise_exception_err_ra(env, EXCP0D_GPF, new_ss & 0xfffc, ra);
            dpl = (ss_e2 >> DESC_DPL_SHIFT) & 3;
            if (dpl != rpl)
                raise_exception_err_ra(env, EXCP0D_GPF, new_ss & 0xfffc, ra);
            if (!(ss_e2 & DESC_P_MASK))
                raise_exception_err_ra(env, EXCP0B_NOSEG, new_ss & 0xfffc, ra);
            cpu_x86_load_seg_cache(env, R_SS, new_ss, get_seg_base(ss_e1, ss_e2), get_seg_limit(ss_e1, ss_e2), ss_e2);
        }

        cpu_x86_load_seg_cache(env, R_CS, new_cs, get_seg_base(e1, e2), get_seg_limit(e1, e2), e2);
        cpu_x86_set_cpl(env, rpl);
        sp = new_esp;
#ifdef TARGET_X86_64
        if (env->hflags & HF_CS64_MASK)
            sp_mask = -1;
        else
#endif
            sp_mask = get_sp_mask(ss_e2);

        /* validate data segments */
        validate_seg(R_ES, rpl);
        validate_seg(R_DS, rpl);
        validate_seg(R_FS, rpl);
        validate_seg(R_GS, rpl);

        sp += addend;
    }
    SET_ESP(sp, sp_mask);
    env->eip = new_eip;
    WR_se_eip(env, new_eip);
    if (is_iret) {
        /* NOTE: 'cpl' is the _old_ CPL */
        eflags_mask = TF_MASK | AC_MASK | ID_MASK | RF_MASK | NT_MASK;
        if (cpl == 0)
            eflags_mask |= IOPL_MASK;
        iopl = (env->mflags >> IOPL_SHIFT) & 3;
        if (cpl <= iopl)
            eflags_mask |= IF_MASK;
        if (shift == 0)
            eflags_mask &= 0xffff;

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
        if (symb_new_eflags == NULL) { // 16-bit case no one cares about, let it be concrete
            load_eflags(new_eflags, eflags_mask);
        } else {
            se_load_eflags(mgr, symb_new_eflags, eflags_mask);
            g_sqi.expr.clear(mgr);
        }
#else
        load_eflags(new_eflags, eflags_mask);
#endif
    }

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (cpl != rpl && unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, rpl);
    }
#endif

    return;

return_to_vm86:
    POPL(ssp, sp, sp_mask, new_esp);
    POPL(ssp, sp, sp_mask, new_ss);
    POPL(ssp, sp, sp_mask, new_es);
    POPL(ssp, sp, sp_mask, new_ds);
    POPL(ssp, sp, sp_mask, new_fs);
    POPL(ssp, sp, sp_mask, new_gs);

/* modify processor state */
#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) && !defined(STATIC_TRANSLATOR)
    se_load_eflags(mgr, symb_new_eflags,
                   TF_MASK | AC_MASK | ID_MASK | IF_MASK | IOPL_MASK | VM_MASK | NT_MASK | VIF_MASK | VIP_MASK);

    g_sqi.expr.clear(mgr);
#else
    load_eflags(new_eflags,
                TF_MASK | AC_MASK | ID_MASK | IF_MASK | IOPL_MASK | VM_MASK | NT_MASK | VIF_MASK | VIP_MASK);
#endif

    load_seg_vm(R_CS, new_cs & 0xffff);
    cpu_x86_set_cpl(env, 3);
    load_seg_vm(R_SS, new_ss & 0xffff);
    load_seg_vm(R_ES, new_es & 0xffff);
    load_seg_vm(R_DS, new_ds & 0xffff);
    load_seg_vm(R_FS, new_fs & 0xffff);
    load_seg_vm(R_GS, new_gs & 0xffff);

    env->eip = new_eip & 0xffff;
    WR_se_eip(env, new_eip);
    ESP_W(new_esp);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, 3);
    }
#endif
}

void helper_iret_protected(int shift, int next_eip) {
    int tss_selector, type;
    uint32_t e1, e2;

    /* specific case for TSS */
    if (env->mflags & NT_MASK) {
#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK)
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
#endif
        tss_selector = cpu_lduw_kernel(env, env->tr.base + 0);
        if (tss_selector & 4)
            raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, GETPC());
        if (load_segment(&e1, &e2, tss_selector) != 0)
            raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, GETPC());
        type = (e2 >> DESC_TYPE_SHIFT) & 0x17;
        /* NOTE: we check both segment and busy TSS */
        if (type != 3)
            raise_exception_err_ra(env, EXCP0A_TSS, tss_selector & 0xfffc, GETPC());
        switch_tss(env, tss_selector, e1, e2, SWITCH_TSS_IRET, next_eip, GETPC());
    } else {
        helper_ret_protected(env, shift, 1, 0, GETPC());
    }
    env->hflags2 &= ~HF2_NMI_MASK;
}

void helper_lret_protected(int shift, int addend) {
    helper_ret_protected(env, shift, 0, addend, GETPC());
}

void helper_sysenter(void) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int cpl = env->hflags & HF_CPL_MASK;
#endif

    if (env->sysenter_cs == 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    env->mflags &= ~(VM_MASK | IF_MASK | RF_MASK);
    cpu_x86_set_cpl(env, 0);

#ifdef TARGET_X86_64
    if (env->hflags & HF_LMA_MASK) {
        cpu_x86_load_seg_cache(env, R_CS, env->sysenter_cs & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
                                   DESC_A_MASK | DESC_L_MASK);
    } else
#endif
    {
        cpu_x86_load_seg_cache(env, R_CS, env->sysenter_cs & 0xfffc, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
                                   DESC_A_MASK);
    }
    cpu_x86_load_seg_cache(env, R_SS, (env->sysenter_cs + 8) & 0xfffc, 0, 0xffffffff,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK);
    ESP_W(env->sysenter_esp);
    EIP = env->sysenter_eip;
    WR_se_eip(env, EIP);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, 0);
    }
#endif
}

void helper_sysexit(int dflag) {
    int cpl;

    cpl = env->hflags & HF_CPL_MASK;
    if (env->sysenter_cs == 0 || cpl != 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    cpu_x86_set_cpl(env, 3);
#ifdef TARGET_X86_64
    if (dflag == 2) {
        cpu_x86_load_seg_cache(env, R_CS, ((env->sysenter_cs + 32) & 0xfffc) | 3, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK | DESC_L_MASK);
        cpu_x86_load_seg_cache(env, R_SS, ((env->sysenter_cs + 40) & 0xfffc) | 3, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_W_MASK | DESC_A_MASK);
    } else
#endif
    {
        cpu_x86_load_seg_cache(env, R_CS, ((env->sysenter_cs + 16) & 0xfffc) | 3, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_SS, ((env->sysenter_cs + 24) & 0xfffc) | 3, 0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_W_MASK | DESC_A_MASK);
    }
    ESP_W(ECX);
    EIP = EDX;
    WR_se_eip(env, EIP);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, 3);
    }
#endif
}

target_ulong helper_read_crN(int reg) {
    target_ulong val;

    helper_svm_check_intercept_param(SVM_EXIT_READ_CR0 + reg, 0);
    switch (reg) {
        default:
            val = env->cr[reg];
            break;
        case 8:
            val = env->v_tpr;
            break;
    }
    return val;
}

void helper_write_crN(int reg, target_ulong t0) {
    helper_svm_check_intercept_param(SVM_EXIT_WRITE_CR0 + reg, 0);
    switch (reg) {
        case 0:
            cpu_x86_update_cr0(env, t0);
            break;
        case 3:
            cpu_x86_update_cr3(env, t0);
            break;
        case 4:
            cpu_x86_update_cr4(env, t0);
            break;
        case 8:
            env->v_tpr = t0 & 0x0f;

            // Give a chance to the KVM client to inject any
            // pending interrupts. Failing to exit the CPU loop
            // may cause missed interrupts in the guest and
            // result in various lock ups.
            cpu_exit(env);
            break;
        default:
            env->cr[reg] = t0;
            break;
    }
}

void helper_movl_drN_T0(int reg, target_ulong t0) {
    int i;

    if (reg < 4) {
        hw_breakpoint_remove(env, reg);
        env->dr[reg] = t0;
        hw_breakpoint_insert(env, reg);
    } else if (reg == 7) {
        for (i = 0; i < 4; i++)
            hw_breakpoint_remove(env, i);
        env->dr[7] = t0;
        for (i = 0; i < 4; i++)
            hw_breakpoint_insert(env, i);
    } else
        env->dr[reg] = t0;
}

void helper_lmsw(target_ulong t0) {
    /* only 4 lower bits of CR0 are modified. PE cannot be set to zero
       if already set to one. */
    t0 = (env->cr[0] & ~0xe) | (t0 & 0xf);
    helper_write_crN(0, t0);
}

void helper_clts(void) {
    env->cr[0] &= ~CR0_TS_MASK;
    env->hflags &= ~HF_TS_MASK;
}

void helper_invlpg(target_ulong addr) {
    helper_svm_check_intercept_param(SVM_EXIT_INVLPG, 0);
    tlb_flush_page(env, addr);
}

void helper_rdtsc(void) {
    uint64_t val;

    if ((env->cr[4] & CR4_TSD_MASK) && ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    helper_svm_check_intercept_param(SVM_EXIT_RDTSC, 0);

    val = cpu_get_tsc() + env->tsc_offset;
    EAX_W((uint32_t) (val));
    EDX_W((uint32_t) (val >> 32));
}

void helper_rdtscp(void) {
    helper_rdtsc();
    ECX_W((uint32_t) (env->tsc_aux));
}

void helper_rdpmc(void) {
    if ((env->cr[4] & CR4_PCE_MASK) && ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    helper_svm_check_intercept_param(SVM_EXIT_RDPMC, 0);

    /* currently unimplemented */
    raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
}

void helper_wrmsr_v(target_ulong index, uint64_t val) {

    switch ((uint32_t) index) {
        case MSR_IA32_SYSENTER_CS:
            env->sysenter_cs = val & 0xffff;
            break;
        case MSR_IA32_SYSENTER_ESP:
            env->sysenter_esp = val;
            break;
        case MSR_IA32_SYSENTER_EIP:
            env->sysenter_eip = val;
            break;
        case MSR_IA32_APICBASE:
            env->v_apic_base = val;
            break;
        case MSR_EFER: {
            uint64_t update_mask;
            update_mask = 0;
            if (env->cpuid.cpuid_ext2_features & CPUID_EXT2_SYSCALL)
                update_mask |= MSR_EFER_SCE;
            if (env->cpuid.cpuid_ext2_features & CPUID_EXT2_LM)
                update_mask |= MSR_EFER_LME;
            if (env->cpuid.cpuid_ext2_features & CPUID_EXT2_FFXSR)
                update_mask |= MSR_EFER_FFXSR;
            if (env->cpuid.cpuid_ext2_features & CPUID_EXT2_NX)
                update_mask |= MSR_EFER_NXE;
            if (env->cpuid.cpuid_ext3_features & CPUID_EXT3_SVM)
                update_mask |= MSR_EFER_SVME;
            if (env->cpuid.cpuid_ext2_features & CPUID_EXT2_FFXSR)
                update_mask |= MSR_EFER_FFXSR;
            cpu_load_efer(env, (env->efer & ~update_mask) | (val & update_mask));
        } break;
        case MSR_STAR:
            env->star = val;
            break;
        case MSR_PAT:
            env->pat = val;
            break;
        case MSR_VM_HSAVE_PA:
            env->vm_hsave = val;
            break;
#ifdef TARGET_X86_64
        case MSR_LSTAR:
            env->lstar = val;
            break;
        case MSR_CSTAR:
            env->cstar = val;
            break;
        case MSR_FMASK:
            env->fmask = val;
            break;
        case MSR_FSBASE:
            env->segs[R_FS].base = val;
            break;
        case MSR_GSBASE:
            env->segs[R_GS].base = val;
            break;
        case MSR_KERNELGSBASE:
            env->kernelgsbase = val;
            break;
#endif
        case MSR_MTRRphysBase(0):
        case MSR_MTRRphysBase(1):
        case MSR_MTRRphysBase(2):
        case MSR_MTRRphysBase(3):
        case MSR_MTRRphysBase(4):
        case MSR_MTRRphysBase(5):
        case MSR_MTRRphysBase(6):
        case MSR_MTRRphysBase(7):
            env->mtrr_var[((uint32_t) index - MSR_MTRRphysBase(0)) / 2].base = val;
            break;
        case MSR_MTRRphysMask(0):
        case MSR_MTRRphysMask(1):
        case MSR_MTRRphysMask(2):
        case MSR_MTRRphysMask(3):
        case MSR_MTRRphysMask(4):
        case MSR_MTRRphysMask(5):
        case MSR_MTRRphysMask(6):
        case MSR_MTRRphysMask(7):
            env->mtrr_var[((uint32_t) index - MSR_MTRRphysMask(0)) / 2].mask = val;
            break;
        case MSR_MTRRfix64K_00000:
            env->mtrr_fixed[(uint32_t) index - MSR_MTRRfix64K_00000] = val;
            break;
        case MSR_MTRRfix16K_80000:
        case MSR_MTRRfix16K_A0000:
            env->mtrr_fixed[(uint32_t) index - MSR_MTRRfix16K_80000 + 1] = val;
            break;
        case MSR_MTRRfix4K_C0000:
        case MSR_MTRRfix4K_C8000:
        case MSR_MTRRfix4K_D0000:
        case MSR_MTRRfix4K_D8000:
        case MSR_MTRRfix4K_E0000:
        case MSR_MTRRfix4K_E8000:
        case MSR_MTRRfix4K_F0000:
        case MSR_MTRRfix4K_F8000:
            env->mtrr_fixed[(uint32_t) index - MSR_MTRRfix4K_C0000 + 3] = val;
            break;
        case MSR_MTRRdefType:
            env->mtrr_deftype = val;
            break;
        case MSR_MCG_STATUS:
            env->mcg_status = val;
            break;
        case MSR_MCG_CTL:
            if ((env->mcg_cap & MCG_CTL_P) && (val == 0 || val == ~(uint64_t) 0))
                env->mcg_ctl = val;
            break;
        case MSR_TSC_AUX:
            env->tsc_aux = val;
            break;
        case MSR_IA32_MISC_ENABLE:
            env->msr_ia32_misc_enable = val;
            break;
        default:
            if ((uint32_t) index >= MSR_MC0_CTL && (uint32_t) index < MSR_MC0_CTL + (4 * env->mcg_cap & 0xff)) {
                uint32_t offset = (uint32_t) index - MSR_MC0_CTL;
                if ((offset & 0x3) != 0 || (val == 0 || val == ~(uint64_t) 0))
                    env->mce_banks[offset] = val;
                break;
            }
            /* XXX: exception ? */
            break;
    }
}

void helper_wrmsr(void) {
    uint64_t val;

    helper_svm_check_intercept_param(SVM_EXIT_MSR, 1);

    val = ((uint32_t) EAX) | ((uint64_t) ((uint32_t) EDX) << 32);
    helper_wrmsr_v(ECX, val);
}

uint64_t helper_rdmsr_v(uint64_t index) {
    uint64_t val;

    switch ((uint32_t) index) {
        case MSR_IA32_SYSENTER_CS:
            val = env->sysenter_cs;
            break;
        case MSR_IA32_SYSENTER_ESP:
            val = env->sysenter_esp;
            break;
        case MSR_IA32_SYSENTER_EIP:
            val = env->sysenter_eip;
            break;
        case MSR_IA32_APICBASE:
            val = env->v_apic_base;
            break;
        case MSR_EFER:
            val = env->efer;
            break;
        case MSR_STAR:
            val = env->star;
            break;
        case MSR_PAT:
            val = env->pat;
            break;
        case MSR_VM_HSAVE_PA:
            val = env->vm_hsave;
            break;
        case MSR_IA32_PERF_STATUS:
            /* tsc_increment_by_tick */
            val = 1000ULL;
            /* CPU multiplier */
            val |= (((uint64_t) 4ULL) << 40);
            break;
#ifdef TARGET_X86_64
        case MSR_LSTAR:
            val = env->lstar;
            break;
        case MSR_CSTAR:
            val = env->cstar;
            break;
        case MSR_FMASK:
            val = env->fmask;
            break;
        case MSR_FSBASE:
            val = env->segs[R_FS].base;
            break;
        case MSR_GSBASE:
            val = env->segs[R_GS].base;
            break;
        case MSR_KERNELGSBASE:
            val = env->kernelgsbase;
            break;
        case MSR_TSC_AUX:
            val = env->tsc_aux;
            break;
#endif
        case MSR_MTRRphysBase(0):
        case MSR_MTRRphysBase(1):
        case MSR_MTRRphysBase(2):
        case MSR_MTRRphysBase(3):
        case MSR_MTRRphysBase(4):
        case MSR_MTRRphysBase(5):
        case MSR_MTRRphysBase(6):
        case MSR_MTRRphysBase(7):
            val = env->mtrr_var[((uint32_t) index - MSR_MTRRphysBase(0)) / 2].base;
            break;
        case MSR_MTRRphysMask(0):
        case MSR_MTRRphysMask(1):
        case MSR_MTRRphysMask(2):
        case MSR_MTRRphysMask(3):
        case MSR_MTRRphysMask(4):
        case MSR_MTRRphysMask(5):
        case MSR_MTRRphysMask(6):
        case MSR_MTRRphysMask(7):
            val = env->mtrr_var[((uint32_t) index - MSR_MTRRphysMask(0)) / 2].mask;
            break;
        case MSR_MTRRfix64K_00000:
            val = env->mtrr_fixed[0];
            break;
        case MSR_MTRRfix16K_80000:
        case MSR_MTRRfix16K_A0000:
            val = env->mtrr_fixed[(uint32_t) index - MSR_MTRRfix16K_80000 + 1];
            break;
        case MSR_MTRRfix4K_C0000:
        case MSR_MTRRfix4K_C8000:
        case MSR_MTRRfix4K_D0000:
        case MSR_MTRRfix4K_D8000:
        case MSR_MTRRfix4K_E0000:
        case MSR_MTRRfix4K_E8000:
        case MSR_MTRRfix4K_F0000:
        case MSR_MTRRfix4K_F8000:
            val = env->mtrr_fixed[(uint32_t) index - MSR_MTRRfix4K_C0000 + 3];
            break;
        case MSR_MTRRdefType:
            val = env->mtrr_deftype;
            break;
        case MSR_MTRRcap:
            if (env->cpuid.cpuid_features & CPUID_MTRR)
                val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT | MSR_MTRRcap_WC_SUPPORTED;
            else
                /* XXX: exception ? */
                val = 0;
            break;
        case MSR_MCG_CAP:
            val = env->mcg_cap;
            break;
        case MSR_MCG_CTL:
            if (env->mcg_cap & MCG_CTL_P)
                val = env->mcg_ctl;
            else
                val = 0;
            break;
        case MSR_MCG_STATUS:
            val = env->mcg_status;
            break;
        case MSR_IA32_MISC_ENABLE:
            val = env->msr_ia32_misc_enable;
            break;
        default:
            if ((uint32_t) index >= MSR_MC0_CTL && (uint32_t) index < MSR_MC0_CTL + (4 * env->mcg_cap & 0xff)) {
                uint32_t offset = (uint32_t) index - MSR_MC0_CTL;
                val = env->mce_banks[offset];
                break;
            }
            /* XXX: exception ? */
            val = 0;
            break;
    }

    return val;
}

void helper_rdmsr(void) {
    uint64_t val;

    helper_svm_check_intercept_param(SVM_EXIT_MSR, 0);

    val = helper_rdmsr_v((uint32_t) ECX);
    EAX_W((uint32_t) (val));
    EDX_W((uint32_t) (val >> 32));
}

target_ulong helper_lsl(target_ulong selector1) {
    unsigned int limit;
    uint32_t e1, e2, eflags, selector;
    int rpl, dpl, cpl, type;

    selector = selector1 & 0xffff;
    eflags = helper_cc_compute_all(CC_OP);
    if ((selector & 0xfffc) == 0)
        goto fail;
    if (load_segment(&e1, &e2, selector) != 0)
        goto fail;
    rpl = selector & 3;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_S_MASK) {
        if ((e2 & DESC_CS_MASK) && (e2 & DESC_C_MASK)) {
            /* conforming */
        } else {
            if (dpl < cpl || dpl < rpl)
                goto fail;
        }
    } else {
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        switch (type) {
            case 1:
            case 2:
            case 3:
            case 9:
            case 11:
                break;
            default:
                goto fail;
        }
        if (dpl < cpl || dpl < rpl) {
        fail:
            CC_SRC_W(eflags & ~CC_Z);
            return 0;
        }
    }
    limit = get_seg_limit(e1, e2);
    CC_SRC_W(eflags | CC_Z);
    return limit;
}

target_ulong helper_lar(target_ulong selector1) {
    uint32_t e1, e2, eflags, selector;
    int rpl, dpl, cpl, type;

    selector = selector1 & 0xffff;
    eflags = helper_cc_compute_all(CC_OP);
    if ((selector & 0xfffc) == 0)
        goto fail;
    if (load_segment(&e1, &e2, selector) != 0)
        goto fail;
    rpl = selector & 3;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_S_MASK) {
        if ((e2 & DESC_CS_MASK) && (e2 & DESC_C_MASK)) {
            /* conforming */
        } else {
            if (dpl < cpl || dpl < rpl)
                goto fail;
        }
    } else {
        type = (e2 >> DESC_TYPE_SHIFT) & 0xf;
        switch (type) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 9:
            case 11:
            case 12:
                break;
            default:
                goto fail;
        }
        if (dpl < cpl || dpl < rpl) {
        fail:
            CC_SRC_W(eflags & ~CC_Z);
            return 0;
        }
    }
    CC_SRC_W(eflags | CC_Z);
    return e2 & 0x00f0ff00;
}

void helper_verr(target_ulong selector1) {
    uint32_t e1, e2, eflags, selector;
    int rpl, dpl, cpl;

    selector = selector1 & 0xffff;
    eflags = helper_cc_compute_all(CC_OP);
    if ((selector & 0xfffc) == 0)
        goto fail;
    if (load_segment(&e1, &e2, selector) != 0)
        goto fail;
    if (!(e2 & DESC_S_MASK))
        goto fail;
    rpl = selector & 3;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_CS_MASK) {
        if (!(e2 & DESC_R_MASK))
            goto fail;
        if (!(e2 & DESC_C_MASK)) {
            if (dpl < cpl || dpl < rpl)
                goto fail;
        }
    } else {
        if (dpl < cpl || dpl < rpl) {
        fail:
            CC_SRC_W(eflags & ~CC_Z);
            return;
        }
    }
    CC_SRC_W(eflags | CC_Z);
}

void helper_verw(target_ulong selector1) {
    uint32_t e1, e2, eflags, selector;
    int rpl, dpl, cpl;

    selector = selector1 & 0xffff;
    eflags = helper_cc_compute_all(CC_OP);
    if ((selector & 0xfffc) == 0)
        goto fail;
    if (load_segment(&e1, &e2, selector) != 0)
        goto fail;
    if (!(e2 & DESC_S_MASK))
        goto fail;
    rpl = selector & 3;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->hflags & HF_CPL_MASK;
    if (e2 & DESC_CS_MASK) {
        goto fail;
    } else {
        if (dpl < cpl || dpl < rpl)
            goto fail;
        if (!(e2 & DESC_W_MASK)) {
        fail:
            CC_SRC_W(eflags & ~CC_Z);
            return;
        }
    }
    CC_SRC_W(eflags | CC_Z);
}

/* x87 FPU helpers */
static inline double floatx80_to_double(floatx80 a) {
    union {
        float64 f64;
        double d;
    } u;

    u.f64 = floatx80_to_float64(a, &env->fp_status);
    return u.d;
}

static inline floatx80 double_to_floatx80(double a) {
    union {
        float64 f64;
        double d;
    } u;

    u.d = a;
    return float64_to_floatx80(u.f64, &env->fp_status);
}

static void fpu_set_exception(int mask) {
    FPUS_W(FPUS | mask);
    if (FPUS & (~FPUC & FPUC_EM))
        FPUS_W(FPUS | FPUS_SE | FPUS_B);
}

static inline floatx80 helper_fdiv(floatx80 a, floatx80 b) {
    if (floatx80_is_zero(b)) {
        fpu_set_exception(FPUS_ZE);
    }
    return floatx80_div(a, b, &env->fp_status);
}

static void fpu_raise_exception(CPUX86State *env, uintptr_t ra) {
    if (env->cr[0] & CR0_NE_MASK) {
        raise_exception_ra(env, EXCP10_COPR, ra);
    } else {
        perror("Not implemented");
    }
}

void helper_flds_FT0(uint32_t val) {
    union {
        float32 f;
        uint32_t i;
    } u;
    u.i = val;
    FT0_W((float32_to_floatx80(u.f, &env->fp_status)));
}

void helper_fldl_FT0(uint64_t val) {
    union {
        float64 f;
        uint64_t i;
    } u;
    u.i = val;
    FT0_W(float64_to_floatx80(u.f, &env->fp_status));
}

void helper_fildl_FT0(int32_t val) {
    FT0_W(int32_to_floatx80(val, &env->fp_status));
}

void helper_flds_ST0(uint32_t val) {
    int new_fpstt;
    union {
        float32 f;
        uint32_t i;
    } u;
    new_fpstt = (FPSTT - 1) & 7;
    u.i = val;
    WR_cpu_fp80(env, fpregs[new_fpstt].d, float32_to_floatx80(u.f, &env->fp_status));
    FPSTT_W(new_fpstt);
    FPTAGS_W(new_fpstt, 0); /* validate stack entry */
}

void helper_fldl_ST0(uint64_t val) {
    int new_fpstt;
    union {
        float64 f;
        uint64_t i;
    } u;
    new_fpstt = (FPSTT - 1) & 7;
    u.i = val;
    WR_cpu_fp80(env, fpregs[new_fpstt].d, float64_to_floatx80(u.f, &env->fp_status));
    FPSTT_W(new_fpstt);
    FPTAGS_W(new_fpstt, 0); /* validate stack entry */
}

void helper_fildl_ST0(int32_t val) {
    int new_fpstt;
    new_fpstt = (FPSTT - 1) & 7;
    WR_cpu_fp80(env, fpregs[new_fpstt].d, int32_to_floatx80(val, &env->fp_status));
    FPSTT_W(new_fpstt);
    FPTAGS_W(new_fpstt, 0); /* validate stack entry */
}

void helper_fildll_ST0(int64_t val) {
    int new_fpstt;
    new_fpstt = (FPSTT - 1) & 7;
    WR_cpu_fp80(env, fpregs[new_fpstt].d, int64_to_floatx80(val, &env->fp_status));
    FPSTT_W(new_fpstt);
    FPTAGS_W(new_fpstt, 0); /* validate stack entry */
}

uint32_t helper_fsts_ST0(void) {
    union {
        float32 f;
        uint32_t i;
    } u;
    u.f = floatx80_to_float32(ST0, &env->fp_status);
    return u.i;
}

uint64_t helper_fstl_ST0(void) {
    union {
        float64 f;
        uint64_t i;
    } u;
    u.f = floatx80_to_float64(ST0, &env->fp_status);
    return u.i;
}

int32_t helper_fist_ST0(void) {
    int32_t val;
    val = floatx80_to_int32(ST0, &env->fp_status);
    if (val != (int16_t) val)
        val = -32768;
    return val;
}

int32_t helper_fistl_ST0(void) {
    int32_t val;
    val = floatx80_to_int32(ST0, &env->fp_status);
    return val;
}

int64_t helper_fistll_ST0(void) {
    int64_t val;
    val = floatx80_to_int64(ST0, &env->fp_status);
    return val;
}

int32_t helper_fistt_ST0(void) {
    int32_t val;
    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    if (val != (int16_t) val)
        val = -32768;
    return val;
}

int32_t helper_fisttl_ST0(void) {
    int32_t val;
    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    return val;
}

int64_t helper_fisttll_ST0(void) {
    int64_t val;
    val = floatx80_to_int64_round_to_zero(ST0, &env->fp_status);
    return val;
}

void helper_fldt_ST0(target_ulong ptr) {
    int new_fpstt;
    new_fpstt = (FPSTT - 1) & 7;
    WR_cpu_fp80(env, fpregs[new_fpstt].d, helper_fldt(ptr));
    FPSTT_W(new_fpstt);
    FPTAGS_W(new_fpstt, 0); /* validate stack entry */
}

void helper_fstt_ST0(target_ulong ptr) {
    helper_fstt(ST0, ptr);
}

void helper_fpush(void) {
    fpush();
}

void helper_fpop(void) {
    fpop();
}

void helper_fdecstp(void) {
    FPSTT_W((FPSTT - 1) & 7);
    FPUS_W(FPUS & (~0x4700));
}

void helper_fincstp(void) {
    FPSTT_W((FPSTT + 1) & 7);
    FPUS_W(FPUS & (~0x4700));
}

/* FPU move */

void helper_ffree_STN(int st_index) {
    FPTAGS_W(((FPSTT + st_index) & 7), 1);
}

void helper_fmov_ST0_FT0(void) {
    ST0_W(FT0);
}

void helper_fmov_FT0_STN(int st_index) {
    FT0_W(ST(st_index));
}

void helper_fmov_ST0_STN(int st_index) {
    ST0_W(ST(st_index));
}

void helper_fmov_STN_ST0(int st_index) {
    ST_W(st_index, ST0);
}

void helper_fxchg_ST0_STN(int st_index) {
    floatx80 tmp;
    tmp = ST(st_index);
    ST_W(st_index, ST0);
    ST0_W(tmp);
}

/* FPU operations */

static const int fcom_ccval[4] = {0x0100, 0x4000, 0x0000, 0x4500};

void helper_fcom_ST0_FT0(void) {
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    FPUS_W((FPUS & ~0x4500) | fcom_ccval[ret + 1]);
}

void helper_fucom_ST0_FT0(void) {
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    FPUS_W((FPUS & ~0x4500) | fcom_ccval[ret + 1]);
}

static const int fcomi_ccval[4] = {CC_C, CC_Z, 0, CC_Z | CC_P | CC_C};

void helper_fcomi_ST0_FT0(void) {
    int eflags;
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    eflags = helper_cc_compute_all(CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC_W(eflags);
}

void helper_fucomi_ST0_FT0(void) {
    int eflags;
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    eflags = helper_cc_compute_all(CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC_W(eflags);
}

void helper_fadd_ST0_FT0(void) {
    ST0_W(floatx80_add(ST0, FT0, &env->fp_status));
}

void helper_fmul_ST0_FT0(void) {
    ST0_W(floatx80_mul(ST0, FT0, &env->fp_status));
}

void helper_fsub_ST0_FT0(void) {
    ST0_W(floatx80_sub(ST0, FT0, &env->fp_status));
}

void helper_fsubr_ST0_FT0(void) {
    ST0_W(floatx80_sub(FT0, ST0, &env->fp_status));
}

void helper_fdiv_ST0_FT0(void) {
    ST0_W(helper_fdiv(ST0, FT0));
}

void helper_fdivr_ST0_FT0(void) {
    ST0_W(helper_fdiv(FT0, ST0));
}

/* fp operations between STN and ST0 */

void helper_fadd_STN_ST0(int st_index) {
    ST_W(st_index, floatx80_add(ST(st_index), ST0, &env->fp_status));
}

void helper_fmul_STN_ST0(int st_index) {
    ST_W(st_index, floatx80_mul(ST(st_index), ST0, &env->fp_status));
}

void helper_fsub_STN_ST0(int st_index) {
    ST_W(st_index, floatx80_sub(ST(st_index), ST0, &env->fp_status));
}

void helper_fsubr_STN_ST0(int st_index) {
    ST_W(st_index, floatx80_sub(ST0, ST(st_index), &env->fp_status));
}

void helper_fdiv_STN_ST0(int st_index) {
#if 0
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(*p, ST0);
#endif
    floatx80 v = ST(st_index);
    ST_W(st_index, helper_fdiv(v, ST0));
}

void helper_fdivr_STN_ST0(int st_index) {
#if 0
    floatx80 *p;
    p = &ST(st_index);
    *p = helper_fdiv(ST0, *p);
#endif
    floatx80 v = ST(st_index);
    ST_W(st_index, helper_fdiv(ST0, v));
}

/* misc FPU operations */
void helper_fchs_ST0(void) {
    ST0_W(floatx80_chs(ST0));
}

void helper_fabs_ST0(void) {
    ST0_W(floatx80_abs(ST0));
}

void helper_fld1_ST0(void) {
    ST0_W(floatx80_one);
}

void helper_fldl2t_ST0(void) {
    ST0_W(floatx80_l2t);
}

void helper_fldl2e_ST0(void) {
    ST0_W(floatx80_l2e);
}

void helper_fldpi_ST0(void) {
    ST0_W(floatx80_pi);
}

void helper_fldlg2_ST0(void) {
    ST0_W(floatx80_lg2);
}

void helper_fldln2_ST0(void) {
    ST0_W(floatx80_ln2);
}

void helper_fldz_ST0(void) {
    ST0_W(floatx80_zero);
}

void helper_fldz_FT0(void) {
    FT0_W(floatx80_zero);
}

uint32_t helper_fnstsw(void) {
    return (FPUS & ~0x3800) | (FPSTT & 0x7) << 11;
}

uint32_t helper_fnstcw(void) {
    return FPUC;
}

static void update_fp_status(void) {
    int rnd_type;

    /* set rounding mode */
    switch (FPUC & FPU_RC_MASK) {
        default:
        case FPU_RC_NEAR:
            rnd_type = float_round_nearest_even;
            break;
        case FPU_RC_DOWN:
            rnd_type = float_round_down;
            break;
        case FPU_RC_UP:
            rnd_type = float_round_up;
            break;
        case FPU_RC_CHOP:
            rnd_type = float_round_to_zero;
            break;
    }
    set_float_rounding_mode(rnd_type, &env->fp_status);
    switch ((FPUC >> 8) & 3) {
        case 0:
            rnd_type = 32;
            break;
        case 2:
            rnd_type = 64;
            break;
        case 3:
        default:
            rnd_type = 80;
            break;
    }
    set_floatx80_rounding_precision(rnd_type, &env->fp_status);
}

void helper_fldcw(uint32_t val) {
    FPUC_W(val);
    update_fp_status();
}

void helper_fclex(void) {
    FPUS_W(FPUS & 0x7f00);
}

void helper_fwait(void) {
    if (FPUS & FPUS_SE)
        fpu_raise_exception(env, GETPC());
}

void helper_fninit(void) {
    FPUS_W(0);
    FPSTT_W(0);
    FPUC_W(0x37f);
    FPTAGS_W(0, 1);
    FPTAGS_W(1, 1);
    FPTAGS_W(2, 1);
    FPTAGS_W(3, 1);
    FPTAGS_W(4, 1);
    FPTAGS_W(5, 1);
    FPTAGS_W(6, 1);
    FPTAGS_W(7, 1);
}

/* BCD ops */

void helper_fbld_ST0(target_ulong ptr) {
    floatx80 tmp;
    uint64_t val;
    unsigned int v;
    int i;

    val = 0;
    for (i = 8; i >= 0; i--) {
        v = ldub(ptr + i);
        val = (val * 100) + ((v >> 4) * 10) + (v & 0xf);
    }
    tmp = int64_to_floatx80(val, &env->fp_status);
    if (ldub(ptr + 9) & 0x80) {
        floatx80_chs(tmp);
    }
    fpush();
    ST0_W(tmp);
}

void helper_fbst_ST0(target_ulong ptr) {
    int v;
    target_ulong mem_ref, mem_end;
    int64_t val;

    val = floatx80_to_int64(ST0, &env->fp_status);
    mem_ref = ptr;
    mem_end = mem_ref + 9;
    if (val < 0) {
        stb(mem_end, 0x80);
        val = -val;
    } else {
        stb(mem_end, 0x00);
    }
    while (mem_ref < mem_end) {
        if (val == 0)
            break;
        v = val % 100;
        val = val / 100;
        v = ((v / 10) << 4) | (v % 10);
        stb(mem_ref++, v);
    }
    while (mem_ref < mem_end) {
        stb(mem_ref++, 0);
    }
}

void helper_f2xm1(void) {
    double val = floatx80_to_double(ST0);
    val = pow(2.0, val) - 1.0;
    ST0_W(double_to_floatx80(val));
}

void helper_fyl2x(void) {
    double fptemp = floatx80_to_double(ST0);

    if (fptemp > 0.0) {
        fptemp = log(fptemp) / log(2.0); /* log2(ST) */
        fptemp *= floatx80_to_double(ST1);
        ST1_W(double_to_floatx80(fptemp));
        fpop();
    } else {
        FPUS_W(FPUS & (~0x4700));
        FPUS_W(FPUS | 0x400);
    }
}

void helper_fptan(void) {
    double fptemp = floatx80_to_double(ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        FPUS_W(FPUS | 0x400);
    } else {
        fptemp = tan(fptemp);
        ST0_W(double_to_floatx80(fptemp));
        fpush();
        ST0_W(floatx80_one);
        FPUS_W(FPUS & (~0x400)); /* C2 <-- 0 */
        /* the above code is for  |arg| < 2**52 only */
    }
}

void helper_fpatan(void) {
    double fptemp, fpsrcop;

    fpsrcop = floatx80_to_double(ST1);
    fptemp = floatx80_to_double(ST0);
    ST1_W(double_to_floatx80(atan2(fpsrcop, fptemp)));
    fpop();
}

void helper_fxtract(void) {
    CPU_LDoubleU temp;

    temp.d = ST0;

    if (floatx80_is_zero(ST0)) {
        /* Easy way to generate -inf and raising division by 0 exception */
        ST0_W(floatx80_div(floatx80_chs(floatx80_one), floatx80_zero, &env->fp_status));
        fpush();
        ST0_W(temp.d);
    } else {
        int expdif;

        expdif = EXPD(temp) - EXPBIAS;
        /*DP exponent bias*/
        ST0_W(int32_to_floatx80(expdif, &env->fp_status));
        fpush();
        BIASEXPONENT(temp);
        ST0_W(temp.d);
    }
}

void helper_fprem1(void) {
    double st0, st1, dblq, fpsrcop, fptemp;
    CPU_LDoubleU fpsrcop1, fptemp1;
    int expdif;
    signed long long int q;

    st0 = floatx80_to_double(ST0);
    st1 = floatx80_to_double(ST1);

    if (isinf(st0) || isnan(st0) || isnan(st1) || (st1 == 0.0)) {
        ST0_W(double_to_floatx80(0.0 / 0.0)); /* NaN */
        FPUS_W(FPUS & (~0x4700));             /* (C3,C2,C1,C0) <-- 0000 */
        return;
    }

    fpsrcop = st0;
    fptemp = st1;
    fpsrcop1.d = ST0;
    fptemp1.d = ST1;
    expdif = EXPD(fpsrcop1) - EXPD(fptemp1);

    if (expdif < 0) {
        /* optimisation? taken from the AMD docs */
        FPUS_W(FPUS & (~0x4700)); /* (C3,C2,C1,C0) <-- 0000 */
        /* ST0 is unchanged */
        return;
    }

    if (expdif < 53) {
        dblq = fpsrcop / fptemp;
        /* round dblq towards nearest integer */
        dblq = rint(dblq);
        st0 = fpsrcop - fptemp * dblq;

        /* convert dblq to q by truncating towards zero */
        if (dblq < 0.0)
            q = (signed long long int) (-dblq);
        else
            q = (signed long long int) dblq;

        FPUS_W(FPUS & (~0x4700));               /* (C3,C2,C1,C0) <-- 0000 */
                                                /* (C0,C3,C1) <-- (q2,q1,q0) */
        FPUS_W(FPUS | ((q & 0x4) << (8 - 2)));  /* (C0) <-- q2 */
        FPUS_W(FPUS | ((q & 0x2) << (14 - 1))); /* (C3) <-- q1 */
        FPUS_W(FPUS | ((q & 0x1) << (9 - 0)));  /* (C1) <-- q0 */
    } else {
        FPUS_W(FPUS | 0x400); /* C2 <-- 1 */
        fptemp = pow(2.0, expdif - 50);
        fpsrcop = (st0 / st1) / fptemp;
        /* fpsrcop = integer obtained by chopping */
        fpsrcop = (fpsrcop < 0.0) ? -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    ST0_W(double_to_floatx80(st0));
}

void helper_fprem(void) {
    double st0, st1, dblq, fpsrcop, fptemp;
    CPU_LDoubleU fpsrcop1, fptemp1;
    int expdif;
    signed long long int q;

    st0 = floatx80_to_double(ST0);
    st1 = floatx80_to_double(ST1);

    if (isinf(st0) || isnan(st0) || isnan(st1) || (st1 == 0.0)) {
        ST0_W(double_to_floatx80(0.0 / 0.0)); /* NaN */
        FPUS_W(FPUS & (~0x4700));             /* (C3,C2,C1,C0) <-- 0000 */
        return;
    }

    fpsrcop = st0;
    fptemp = st1;
    fpsrcop1.d = ST0;
    fptemp1.d = ST1;
    expdif = EXPD(fpsrcop1) - EXPD(fptemp1);

    if (expdif < 0) {
        /* optimisation? taken from the AMD docs */
        FPUS_W(FPUS & (~0x4700)); /* (C3,C2,C1,C0) <-- 0000 */
        /* ST0 is unchanged */
        return;
    }

    if (expdif < 53) {
        dblq = fpsrcop /*ST0*/ / fptemp /*ST1*/;
        /* round dblq towards zero */
        dblq = (dblq < 0.0) ? ceil(dblq) : floor(dblq);
        st0 = fpsrcop /*ST0*/ - fptemp * dblq;

        /* convert dblq to q by truncating towards zero */
        if (dblq < 0.0)
            q = (signed long long int) (-dblq);
        else
            q = (signed long long int) dblq;

        FPUS_W(FPUS & (~0x4700));               /* (C3,C2,C1,C0) <-- 0000 */
                                                /* (C0,C3,C1) <-- (q2,q1,q0) */
        FPUS_W(FPUS | ((q & 0x4) << (8 - 2)));  /* (C0) <-- q2 */
        FPUS_W(FPUS | ((q & 0x2) << (14 - 1))); /* (C3) <-- q1 */
        FPUS_W(FPUS | ((q & 0x1) << (9 - 0)));  /* (C1) <-- q0 */
    } else {
        int N = 32 + (expdif % 32); /* as per AMD docs */
        FPUS_W(FPUS | 0x400);       /* C2 <-- 1 */
        fptemp = pow(2.0, (double) (expdif - N));
        fpsrcop = (st0 / st1) / fptemp;
        /* fpsrcop = integer obtained by chopping */
        fpsrcop = (fpsrcop < 0.0) ? -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    ST0_W(double_to_floatx80(st0));
}

void helper_fyl2xp1(void) {
    double fptemp = floatx80_to_double(ST0);

    if ((fptemp + 1.0) > 0.0) {
        fptemp = log(fptemp + 1.0) / log(2.0); /* log2(ST+1.0) */
        fptemp *= floatx80_to_double(ST1);
        ST1_W(double_to_floatx80(fptemp));
        fpop();
    } else {
        FPUS_W(FPUS & (~0x4700));
        FPUS_W(FPUS | 0x400);
    }
}

void helper_fsqrt(void) {
    if (floatx80_is_neg(ST0)) {
        FPUS_W(FPUS & (~0x4700)); /* (C3,C2,C1,C0) <-- 0000 */
        FPUS_W(FPUS | 0x400);
    }
    ST0_W(floatx80_sqrt(ST0, &env->fp_status));
}

void helper_fsincos(void) {
    double fptemp = floatx80_to_double(ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        FPUS_W(FPUS | 0x400);
    } else {
        ST0_W(double_to_floatx80(sin(fptemp)));
        fpush();
        ST0_W(double_to_floatx80(cos(fptemp)));
        FPUS_W(FPUS & (~0x400)); /* C2 <-- 0 */
        /* the above code is for  |arg| < 2**63 only */
    }
}

void helper_frndint(void) {
    ST0_W(floatx80_round_to_int(ST0, &env->fp_status));
}

void helper_fscale(void) {
    if (floatx80_is_any_nan(ST1)) {
        ST0_W(ST1);
    } else {
        int n = floatx80_to_int32_round_to_zero(ST1, &env->fp_status);
        ST0_W(floatx80_scalbn(ST0, n, &env->fp_status));
    }
}

void helper_fsin(void) {
    double fptemp = floatx80_to_double(ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        FPUS_W(FPUS | 0x400);
    } else {
        ST0_W(double_to_floatx80(sin(fptemp)));
        FPUS_W(FPUS & (~0x400)); /* C2 <-- 0 */
        /* the above code is for  |arg| < 2**53 only */
    }
}

void helper_fcos(void) {
    double fptemp = floatx80_to_double(ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        FPUS_W(FPUS | 0x400);
    } else {
        ST0_W(double_to_floatx80(cos(fptemp)));
        FPUS_W(FPUS & (~0x400)); /* C2 <-- 0 */
        /* the above code is for  |arg5 < 2**63 only */
    }
}

void helper_fxam_ST0(void) {
    CPU_LDoubleU temp;
    int expdif;

    temp.d = ST0;

    FPUS_W(FPUS & (~0x4700)); /* (C3,C2,C1,C0) <-- 0000 */
    if (SIGND(temp))
        FPUS_W(FPUS | 0x200); /* C1 <-- 1 */

    /* XXX: test fptags too */
    expdif = EXPD(temp);
    if (expdif == MAXEXPD) {
        if (MANTD(temp) == 0x8000000000000000ULL)
            FPUS_W(FPUS | 0x500 /*Infinity*/);
        else
            FPUS_W(FPUS | 0x100 /*NaN*/);
    } else if (expdif == 0) {
        if (MANTD(temp) == 0)
            FPUS_W(FPUS | 0x4000 /*Zero*/);
        else
            FPUS_W(FPUS | 0x4400 /*Denormal*/);
    } else {
        FPUS_W(FPUS | 0x400);
    }
}

void helper_fstenv(target_ulong ptr, int data32) {
    int fpus, fptag, exp, i;
    uint64_t mant;
    CPU_LDoubleU tmp;

    fpus = (FPUS & ~0x3800) | (FPSTT & 0x7) << 11;
    fptag = 0;
    for (i = 7; i >= 0; i--) {
        fptag <<= 2;
        if (FPTAGS(i)) {
            fptag |= 3;
        } else {
            tmp.d = RR_cpu_fp80(env, fpregs[i].d);
            exp = EXPD(tmp);
            mant = MANTD(tmp);
            if (exp == 0 && mant == 0) {
                /* zero */
                fptag |= 1;
            } else if (exp == 0 || exp == MAXEXPD || (mant & (1LL << 63)) == 0) {
                /* NaNs, infinity, denormal */
                fptag |= 2;
            }
        }
    }
    if (data32) {
        /* 32 bit */
        stl(ptr, FPUC);
        stl(ptr + 4, fpus);
        stl(ptr + 8, fptag);
        stl(ptr + 12, 0); /* fpip */
        stl(ptr + 16, 0); /* fpcs */
        stl(ptr + 20, 0); /* fpoo */
        stl(ptr + 24, 0); /* fpos */
    } else {
        /* 16 bit */
        stw(ptr, FPUC);
        stw(ptr + 2, fpus);
        stw(ptr + 4, fptag);
        stw(ptr + 6, 0);
        stw(ptr + 8, 0);
        stw(ptr + 10, 0);
        stw(ptr + 12, 0);
    }
}

void helper_fldenv(target_ulong ptr, int data32) {
    int i, fpus, fptag;

    if (data32) {
        FPUC_W(lduw(ptr));
        fpus = lduw(ptr + 4);
        fptag = lduw(ptr + 8);
    } else {
        FPUC_W(lduw(ptr));
        fpus = lduw(ptr + 2);
        fptag = lduw(ptr + 4);
    }
    FPSTT_W((fpus >> 11) & 7);
    FPUS_W(fpus & ~0x3800);
    for (i = 0; i < 8; i++) {
        FPTAGS_W(i, ((fptag & 3) == 3));
        fptag >>= 2;
    }
}

void helper_fsave(target_ulong ptr, int data32) {
    floatx80 tmp;
    int i;

    helper_fstenv(ptr, data32);

    ptr += (14 << data32);
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(tmp, ptr);
        ptr += 10;
    }

    /* fninit */
    FPUS_W(0);
    FPSTT_W(0);
    FPUC_W(0x37f);
    FPTAGS_W(0, 1);
    FPTAGS_W(1, 1);
    FPTAGS_W(2, 1);
    FPTAGS_W(3, 1);
    FPTAGS_W(4, 1);
    FPTAGS_W(5, 1);
    FPTAGS_W(6, 1);
    FPTAGS_W(7, 1);
}

void helper_frstor(target_ulong ptr, int data32) {
    floatx80 tmp;
    int i;

    helper_fldenv(ptr, data32);
    ptr += (14 << data32);

    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(ptr);
        ST_W(i, tmp);
        ptr += 10;
    }
}

void helper_fxsave(target_ulong ptr, int data64) {
    int fpus, fptag, i, nb_xmm_regs;
    floatx80 tmp;
    target_ulong addr;

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }

    fpus = (FPUS & ~0x3800) | (FPSTT & 0x7) << 11;
    fptag = 0;
    for (i = 0; i < 8; i++) {
        fptag |= (FPTAGS(i) << i);
    }
    stw(ptr, FPUC);
    stw(ptr + 2, fpus);
    stw(ptr + 4, fptag ^ 0xff);
#ifdef TARGET_X86_64
    if (data64) {
        stq(ptr + 0x08, 0); /* rip */
        stq(ptr + 0x10, 0); /* rdp */
    } else
#endif
    {
        stl(ptr + 0x08, 0); /* eip */
        stl(ptr + 0x0c, 0); /* sel  */
        stl(ptr + 0x10, 0); /* dp */
        stl(ptr + 0x14, 0); /* sel  */
    }

    addr = ptr + 0x20;
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(tmp, addr);
        addr += 16;
    }

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        /* XXX: finish it */
        stl(ptr + 0x18, MXCSR);      /* mxcsr */
        stl(ptr + 0x1c, 0x0000ffff); /* mxcsr_mask */
        if (env->hflags & HF_CS64_MASK)
            nb_xmm_regs = 16;
        else
            nb_xmm_regs = 8;
        addr = ptr + 0xa0;
        /* Fast FXSAVE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR) || (env->hflags & HF_CPL_MASK) || !(env->hflags & HF_LMA_MASK)) {
            for (i = 0; i < nb_xmm_regs; i++) {
                stq(addr, RR_cpu_dyn(&env->xmm_regs[i].XMM_Q(0), 8));
                stq(addr + 8, RR_cpu_dyn(&env->xmm_regs[i].XMM_Q(1), 8));
                addr += 16;
            }
        }
    }
}

void helper_fxrstor(target_ulong ptr, int data64) {
    int i, fpus, fptag, nb_xmm_regs;
    floatx80 tmp;
    target_ulong addr;

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
    if (g_sqi.mem.is_vmem_symbolic(ptr, 0x200)) {
        g_sqi.exec.switch_to_symbolic((void *) GETPC());
    }
#endif

    FPUC_W(lduw(ptr));
    fpus = lduw(ptr + 2);
    fptag = lduw(ptr + 4);
    FPSTT_W((fpus >> 11) & 7);
    FPUS_W(fpus & ~0x3800);
    fptag ^= 0xff;
    for (i = 0; i < 8; i++) {
        FPTAGS_W(i, ((fptag >> i) & 1));
    }

    addr = ptr + 0x20;
    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(addr);
        ST_W(i, tmp);
        addr += 16;
    }

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        /* XXX: finish it */
        MXCSR_W(ldl(ptr + 0x18));
        // ldl(ptr + 0x1c);
        if (env->hflags & HF_CS64_MASK)
            nb_xmm_regs = 16;
        else
            nb_xmm_regs = 8;
        addr = ptr + 0xa0;
        /* Fast FXRESTORE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR) || (env->hflags & HF_CPL_MASK) || !(env->hflags & HF_LMA_MASK)) {
            for (i = 0; i < nb_xmm_regs; i++) {
                WR_cpu_dyn(&env->xmm_regs[i].XMM_Q(0), 8, ldq(addr));
                WR_cpu_dyn(&env->xmm_regs[i].XMM_Q(1), 8, ldq(addr + 8));
                addr += 16;
            }
        }
    }
}

void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f) {
    CPU_LDoubleU temp;

    temp.d = f;
    *pmant = temp.l.lower;
    *pexp = temp.l.upper;
}

floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper) {
    CPU_LDoubleU temp;

    temp.l.upper = upper;
    temp.l.lower = mant;
    return temp.d;
}

#ifdef TARGET_X86_64

//#define DEBUG_MULDIV

static void add128(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b) {
    *plow += a;
    /* carry test */
    if (*plow < a)
        (*phigh)++;
    *phigh += b;
}

static void neg128(uint64_t *plow, uint64_t *phigh) {
    *plow = ~*plow;
    *phigh = ~*phigh;
    add128(plow, phigh, 1, 0);
}

/* return TRUE if overflow */
static int div64(uint64_t *plow, uint64_t *phigh, uint64_t b) {
    uint64_t q, r, a1, a0;
    int i, qb, ab;

    a0 = *plow;
    a1 = *phigh;
    if (a1 == 0) {
        q = a0 / b;
        r = a0 % b;
        *plow = q;
        *phigh = r;
    } else {
        if (a1 >= b)
            return 1;
        /* XXX: use a better algorithm */
        for (i = 0; i < 64; i++) {
            ab = a1 >> 63;
            a1 = (a1 << 1) | (a0 >> 63);
            if (ab || a1 >= b) {
                a1 -= b;
                qb = 1;
            } else {
                qb = 0;
            }
            a0 = (a0 << 1) | qb;
        }
#if defined(DEBUG_MULDIV)
        printf("div: 0x%016" PRIx64 "%016" PRIx64 " / 0x%016" PRIx64 ": q=0x%016" PRIx64 " r=0x%016" PRIx64 "\n",
               *phigh, *plow, b, a0, a1);
#endif
        *plow = a0;
        *phigh = a1;
    }
    return 0;
}

/* return TRUE if overflow */
static int idiv64(uint64_t *plow, uint64_t *phigh, int64_t b) {
    int sa, sb;
    sa = ((int64_t) *phigh < 0);
    if (sa)
        neg128(plow, phigh);
    sb = (b < 0);
    if (sb)
        b = -b;
    if (div64(plow, phigh, b) != 0)
        return 1;
    if (sa ^ sb) {
        if (*plow > (1ULL << 63))
            return 1;
        *plow = -*plow;
    } else {
        if (*plow >= (1ULL << 63))
            return 1;
    }
    if (sa)
        *phigh = -*phigh;
    return 0;
}

void helper_mulq_EAX_T0(target_ulong t0) {
    uint64_t r0, r1;

    mulu64(&r0, &r1, EAX, t0);
    EAX_W(r0);
    EDX_W(r1);
    CC_DST_W(r0);
    CC_SRC_W(r1);
}

void helper_imulq_EAX_T0(target_ulong t0) {
    uint64_t r0, r1;

    muls64(&r0, &r1, EAX, t0);
    EAX_W(r0);
    EDX_W(r1);
    CC_DST_W(r0);
    CC_SRC_W(((int64_t) r1 != ((int64_t) r0 >> 63)));
}

target_ulong helper_imulq_T0_T1(target_ulong t0, target_ulong t1) {
    uint64_t r0, r1;

    muls64(&r0, &r1, t0, t1);
    CC_DST_W(r0);
    CC_SRC_W(((int64_t) r1 != ((int64_t) r0 >> 63)));
    return r0;
}

void helper_divq_EAX(target_ulong t0) {
    uint64_t r0, r1;
    if (t0 == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    r0 = EAX;
    r1 = EDX;
    if (div64(&r0, &r1, t0))
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    EAX_W(r0);
    EDX_W(r1);
}

void helper_idivq_EAX(target_ulong t0) {
    uint64_t r0, r1;
    if (t0 == 0) {
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    }
    r0 = EAX;
    r1 = EDX;
    if (idiv64(&r0, &r1, t0))
        raise_exception_ra(env, EXCP00_DIVZ, GETPC());
    EAX_W(r0);
    EDX_W(r1);
}
#endif

static void do_hlt(void) {
    env->hflags &= ~HF_INHIBIT_IRQ_MASK; /* needed if sti is just before */
    env->halted = 1;
    env->exception_index = EXCP_HLT;
    cpu_loop_exit(env);
}

void helper_hlt(int next_eip_addend) {
    helper_svm_check_intercept_param(SVM_EXIT_HLT, 0);
    EIP += next_eip_addend;

    do_hlt();
}

void helper_monitor(target_ulong ptr) {
    if ((uint32_t) ECX != 0)
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    /* XXX: store address ? */
    helper_svm_check_intercept_param(SVM_EXIT_MONITOR, 0);
}

void helper_mwait(int next_eip_addend) {
    if ((uint32_t) ECX != 0)
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    helper_svm_check_intercept_param(SVM_EXIT_MWAIT, 0);
    EIP += next_eip_addend;

    /* XXX: not complete but not completely erroneous */
    if (env->cpu_index != 0 || env->next_cpu != NULL) {
        /* more than one CPU: do not sleep because another CPU may
           wake this one */
    } else {
        do_hlt();
    }
}

void helper_debug(void) {
    env->exception_index = EXCP_DEBUG;
    cpu_loop_exit(env);
}

void helper_reset_rf(void) {
    env->mflags &= ~RF_MASK;
}

#ifndef STATIC_TRANSLATOR
void helper_raise_interrupt(int intno, int next_eip_addend) {
    raise_interrupt(env, intno, 1, 0, next_eip_addend);
}

void helper_raise_exception(int exception_index) {
    raise_exception(env, exception_index);
}
#else
/**
 * In static mode, interrupts are emulated by the
 * run-time library. They behave like normal function calls.
 */
#ifndef SYMBEX_LLVM_LIB
void helper_raise_interrupt(int intno, int next_eip_addend) {
    assert(false && "Can't be called");
}

void helper_raise_exception(int exception_index) {
    assert(false && "Can't be called");
}
#endif
#endif

void helper_cli(void) {
    env->mflags &= ~IF_MASK;
}

void helper_sti(void) {
    env->mflags |= IF_MASK;
}

#if 0
/* vm86plus instructions */
void helper_cli_vm(void)
{
    env->mflags &= ~VIF_MASK;
}

void helper_sti_vm(void)
{
    env->mflags |= VIF_MASK;
    if (env->mflags & VIP_MASK) {
        raise_exception(EXCP0D_GPF);
    }
}
#endif

void helper_set_inhibit_irq(void) {
    env->hflags |= HF_INHIBIT_IRQ_MASK;
}

void helper_reset_inhibit_irq(void) {
    env->hflags &= ~HF_INHIBIT_IRQ_MASK;
}

void helper_boundw(target_ulong a0, int v) {
    int low, high;
    low = ldsw(a0);
    high = ldsw(a0 + 2);
    v = (int16_t) v;
    if (v < low || v > high) {
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(target_ulong a0, int v) {
    int low, high;
    low = ldl(a0);
    high = ldl(a0 + 4);
    if (v < low || v > high) {
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

#define MMUSUFFIX _mmu

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
#undef MMUSUFFIX
#define MMUSUFFIX _mmu_symb
#define _raw      _raw_symb

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#undef _raw
#endif

#ifdef STATIC_TRANSLATOR
void tlb_fill(CPUX86State *env1, target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx, void *retaddr) {
    assert(false);
}

#endif

#if !defined(STATIC_TRANSLATOR)
/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUX86State *env1, target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx, void *retaddr) {
    int ret;

#if defined(CONFIG_SYMBEX)
    if (unlikely(*g_sqi.events.on_tlb_miss_signals_count)) {
        g_sqi.events.on_tlb_miss(addr, is_write, retaddr);
    }
#endif

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    ret = cpu_x86_handle_mmu_fault(env, page_addr, is_write, mmu_idx);
#else
    ret = cpu_x86_handle_mmu_fault(env1, addr, is_write, mmu_idx);
#endif

    if (ret) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
        /* In symbex mode, pass page address instead of addr to cpu_x86_handle_mmu_fault,
           since the latter can be symbolic while the former is always concrete.
           To compensate, we reset fault address here. */
        if (env->exception_index == EXCP0E_PAGE) {
            if (env->intercept_exceptions & (1 << EXCP0E_PAGE))
                stq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2), addr);
            else
                env->cr[2] = addr;
        }
#endif

#if defined(CONFIG_SYMBEX)
        if (unlikely(*g_sqi.events.on_page_fault_signals_count)) {
            g_sqi.events.on_page_fault(addr, is_write, retaddr);
        }
#endif
        raise_exception_err_ra(env, env->exception_index, env->error_code, (uintptr_t) retaddr);
    }
}
#endif

/* Secure Virtual Machine helpers */
static inline void svm_save_seg(target_phys_addr_t addr, const SegmentCache *sc) {
    stw_phys(addr + offsetof(struct vmcb_seg, selector), sc->selector);
    stq_phys(addr + offsetof(struct vmcb_seg, base), sc->base);
    stl_phys(addr + offsetof(struct vmcb_seg, limit), sc->limit);
    stw_phys(addr + offsetof(struct vmcb_seg, attrib), ((sc->flags >> 8) & 0xff) | ((sc->flags >> 12) & 0x0f00));
}

static inline void svm_load_seg(target_phys_addr_t addr, SegmentCache *sc) {
    unsigned int flags;

    sc->selector = lduw_phys(addr + offsetof(struct vmcb_seg, selector));
    sc->base = ldq_phys(addr + offsetof(struct vmcb_seg, base));
    sc->limit = ldl_phys(addr + offsetof(struct vmcb_seg, limit));
    flags = lduw_phys(addr + offsetof(struct vmcb_seg, attrib));
    sc->flags = ((flags & 0xff) << 8) | ((flags & 0x0f00) << 12);
}

static inline void svm_load_seg_cache(target_phys_addr_t addr, CPUX86State *env, int seg_reg) {
    SegmentCache sc1, *sc = &sc1;
    svm_load_seg(addr, sc);
    cpu_x86_load_seg_cache(env, seg_reg, sc->selector, sc->base, sc->limit, sc->flags);
}

void helper_vmrun(int aflag, int next_eip_addend) {
    target_ulong addr;
    uint32_t event_inj;
    uint32_t int_ctl;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int cpl = env->hflags & HF_CPL_MASK;
#endif

    helper_svm_check_intercept_param(SVM_EXIT_VMRUN, 0);

    if (aflag == 2)
        addr = EAX;
    else
        addr = (uint32_t) EAX;

    libcpu_log_mask(CPU_LOG_TB_IN_ASM, "vmrun! " TARGET_FMT_lx "\n", addr);

    env->vm_vmcb = addr;

    /* save the current CPU state in the hsave page */
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.gdtr.base), env->gdt.base);
    stl_phys(env->vm_hsave + offsetof(struct vmcb, save.gdtr.limit), env->gdt.limit);

    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.idtr.base), env->idt.base);
    stl_phys(env->vm_hsave + offsetof(struct vmcb, save.idtr.limit), env->idt.limit);

    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr0), env->cr[0]);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr2), env->cr[2]);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr3), env->cr[3]);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr4), env->cr[4]);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.dr6), env->dr[6]);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.dr7), env->dr[7]);

    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.efer), env->efer);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.rflags), compute_eflags());

    svm_save_seg(env->vm_hsave + offsetof(struct vmcb, save.es), &env->segs[R_ES]);
    svm_save_seg(env->vm_hsave + offsetof(struct vmcb, save.cs), &env->segs[R_CS]);
    svm_save_seg(env->vm_hsave + offsetof(struct vmcb, save.ss), &env->segs[R_SS]);
    svm_save_seg(env->vm_hsave + offsetof(struct vmcb, save.ds), &env->segs[R_DS]);

    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.rip), EIP + next_eip_addend);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.rsp), ESP);
    stq_phys(env->vm_hsave + offsetof(struct vmcb, save.rax), EAX);

    /* load the interception bitmaps so we do not need to access the
       vmcb in svm mode */
    env->intercept = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept));
    env->intercept_cr_read = lduw_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept_cr_read));
    env->intercept_cr_write = lduw_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept_cr_write));
    env->intercept_dr_read = lduw_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept_dr_read));
    env->intercept_dr_write = lduw_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept_dr_write));
    env->intercept_exceptions = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.intercept_exceptions));

    /* enable intercepts */
    env->hflags |= HF_SVMI_MASK;

    env->tsc_offset = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, control.tsc_offset));

    env->gdt.base = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.gdtr.base));
    env->gdt.limit = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, save.gdtr.limit));

    env->idt.base = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.idtr.base));
    env->idt.limit = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, save.idtr.limit));

    /* clear exit_info_2 so we behave like the real hardware */
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2), 0);

    cpu_x86_update_cr0(env, ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr0)));
    cpu_x86_update_cr4(env, ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr4)));
    cpu_x86_update_cr3(env, ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr3)));
    env->cr[2] = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr2));
    int_ctl = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_ctl));
    env->hflags2 &= ~(HF2_HIF_MASK | HF2_VINTR_MASK);
    if (int_ctl & V_INTR_MASKING_MASK) {
        env->v_tpr = int_ctl & V_TPR_MASK;
        env->hflags2 |= HF2_VINTR_MASK;
        if (env->mflags & IF_MASK)
            env->hflags2 |= HF2_HIF_MASK;
    }

    cpu_load_efer(env, ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.efer)));
    env->mflags = 0;
    load_eflags(ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rflags)),
                ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    CC_OP_W(CC_OP_EFLAGS);

    svm_load_seg_cache(env->vm_vmcb + offsetof(struct vmcb, save.es), env, R_ES);
    svm_load_seg_cache(env->vm_vmcb + offsetof(struct vmcb, save.cs), env, R_CS);
    svm_load_seg_cache(env->vm_vmcb + offsetof(struct vmcb, save.ss), env, R_SS);
    svm_load_seg_cache(env->vm_vmcb + offsetof(struct vmcb, save.ds), env, R_DS);

    EIP = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rip));
    env->eip = EIP;
    WR_se_eip(env, env->eip);
    ESP_W(ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rsp)));
    EAX_W(ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rax)));
    env->dr[7] = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.dr7));
    env->dr[6] = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, save.dr6));

    int dpl = ldub_phys(env->vm_vmcb + offsetof(struct vmcb, save.cpl));
    cpu_x86_set_cpl(env, dpl);

    /* FIXME: guest state consistency checks */

    switch (ldub_phys(env->vm_vmcb + offsetof(struct vmcb, control.tlb_ctl))) {
        case TLB_CONTROL_DO_NOTHING:
            break;
        case TLB_CONTROL_FLUSH_ALL_ASID:
            /* FIXME: this is not 100% correct but should work for now */
            tlb_flush(env, 1);
            break;
    }

    env->hflags2 |= HF2_GIF_MASK;

    if (int_ctl & V_IRQ_MASK) {
        env->interrupt_request |= CPU_INTERRUPT_VIRQ;
    }

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, dpl);
    }
#endif

    /* maybe we need to inject an event */
    event_inj = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj));
    if (event_inj & SVM_EVTINJ_VALID) {
        uint8_t vector = event_inj & SVM_EVTINJ_VEC_MASK;
        uint16_t valid_err = event_inj & SVM_EVTINJ_VALID_ERR;
        uint32_t event_inj_err = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj_err));

        libcpu_log_mask(CPU_LOG_TB_IN_ASM, "Injecting(%#hx): ", valid_err);
        /* FIXME: need to implement valid_err */
        switch (event_inj & SVM_EVTINJ_TYPE_MASK) {
            case SVM_EVTINJ_TYPE_INTR:
                env->exception_index = vector;
                env->error_code = event_inj_err;
                env->exception_is_int = 0;
                env->exception_next_eip = -1;
                libcpu_log_mask(CPU_LOG_TB_IN_ASM, "INTR");
                /* XXX: is it always correct ? */
                do_interrupt_all(vector, 0, 0, 0, 1);
                break;
            case SVM_EVTINJ_TYPE_NMI:
                env->exception_index = EXCP02_NMI;
                env->error_code = event_inj_err;
                env->exception_is_int = 0;
                env->exception_next_eip = EIP;
                libcpu_log_mask(CPU_LOG_TB_IN_ASM, "NMI");
                cpu_loop_exit(env);
                break;
            case SVM_EVTINJ_TYPE_EXEPT:
                env->exception_index = vector;
                env->error_code = event_inj_err;
                env->exception_is_int = 0;
                env->exception_next_eip = -1;
                libcpu_log_mask(CPU_LOG_TB_IN_ASM, "EXEPT");
                cpu_loop_exit(env);
                break;
            case SVM_EVTINJ_TYPE_SOFT:
                env->exception_index = vector;
                env->error_code = event_inj_err;
                env->exception_is_int = 1;
                env->exception_next_eip = EIP;
                libcpu_log_mask(CPU_LOG_TB_IN_ASM, "SOFT");
                cpu_loop_exit(env);
                break;
        }
        libcpu_log_mask(CPU_LOG_TB_IN_ASM, " %#x %#x\n", env->exception_index, env->error_code);
    }
}

void helper_vmmcall(void) {
    helper_svm_check_intercept_param(SVM_EXIT_VMMCALL, 0);
    raise_exception_ra(env, EXCP06_ILLOP, GETPC());
}

void helper_vmload(int aflag) {
    target_ulong addr;
    helper_svm_check_intercept_param(SVM_EXIT_VMLOAD, 0);

    if (aflag == 2)
        addr = EAX;
    else
        addr = (uint32_t) EAX;

    libcpu_log_mask(CPU_LOG_TB_IN_ASM, "vmload! " TARGET_FMT_lx "\nFS: %016" PRIx64 " | " TARGET_FMT_lx "\n", addr,
                    ldq_phys(addr + offsetof(struct vmcb, save.fs.base)), env->segs[R_FS].base);

    svm_load_seg_cache(addr + offsetof(struct vmcb, save.fs), env, R_FS);
    svm_load_seg_cache(addr + offsetof(struct vmcb, save.gs), env, R_GS);
    svm_load_seg(addr + offsetof(struct vmcb, save.tr), &env->tr);
    svm_load_seg(addr + offsetof(struct vmcb, save.ldtr), &env->ldt);

#ifdef TARGET_X86_64
    env->kernelgsbase = ldq_phys(addr + offsetof(struct vmcb, save.kernel_gs_base));
    env->lstar = ldq_phys(addr + offsetof(struct vmcb, save.lstar));
    env->cstar = ldq_phys(addr + offsetof(struct vmcb, save.cstar));
    env->fmask = ldq_phys(addr + offsetof(struct vmcb, save.sfmask));
#endif
    env->star = ldq_phys(addr + offsetof(struct vmcb, save.star));
    env->sysenter_cs = ldq_phys(addr + offsetof(struct vmcb, save.sysenter_cs));
    env->sysenter_esp = ldq_phys(addr + offsetof(struct vmcb, save.sysenter_esp));
    env->sysenter_eip = ldq_phys(addr + offsetof(struct vmcb, save.sysenter_eip));
}

void helper_vmsave(int aflag) {
    target_ulong addr;
    helper_svm_check_intercept_param(SVM_EXIT_VMSAVE, 0);

    if (aflag == 2)
        addr = EAX;
    else
        addr = (uint32_t) EAX;

    libcpu_log_mask(CPU_LOG_TB_IN_ASM, "vmsave! " TARGET_FMT_lx "\nFS: %016" PRIx64 " | " TARGET_FMT_lx "\n", addr,
                    ldq_phys(addr + offsetof(struct vmcb, save.fs.base)), env->segs[R_FS].base);

    svm_save_seg(addr + offsetof(struct vmcb, save.fs), &env->segs[R_FS]);
    svm_save_seg(addr + offsetof(struct vmcb, save.gs), &env->segs[R_GS]);
    svm_save_seg(addr + offsetof(struct vmcb, save.tr), &env->tr);
    svm_save_seg(addr + offsetof(struct vmcb, save.ldtr), &env->ldt);

#ifdef TARGET_X86_64
    stq_phys(addr + offsetof(struct vmcb, save.kernel_gs_base), env->kernelgsbase);
    stq_phys(addr + offsetof(struct vmcb, save.lstar), env->lstar);
    stq_phys(addr + offsetof(struct vmcb, save.cstar), env->cstar);
    stq_phys(addr + offsetof(struct vmcb, save.sfmask), env->fmask);
#endif
    stq_phys(addr + offsetof(struct vmcb, save.star), env->star);
    stq_phys(addr + offsetof(struct vmcb, save.sysenter_cs), env->sysenter_cs);
    stq_phys(addr + offsetof(struct vmcb, save.sysenter_esp), env->sysenter_esp);
    stq_phys(addr + offsetof(struct vmcb, save.sysenter_eip), env->sysenter_eip);
}

void helper_stgi(void) {
    helper_svm_check_intercept_param(SVM_EXIT_STGI, 0);
    env->hflags2 |= HF2_GIF_MASK;
}

void helper_clgi(void) {
    helper_svm_check_intercept_param(SVM_EXIT_CLGI, 0);
    env->hflags2 &= ~HF2_GIF_MASK;
}

void helper_skinit(void) {
    helper_svm_check_intercept_param(SVM_EXIT_SKINIT, 0);
    /* XXX: not implemented */
    raise_exception_ra(env, EXCP06_ILLOP, GETPC());
}

void helper_invlpga(int aflag) {
    target_ulong addr;
    helper_svm_check_intercept_param(SVM_EXIT_INVLPGA, 0);

    if (aflag == 2)
        addr = EAX;
    else
        addr = (uint32_t) EAX;

    /* XXX: could use the ASID to see if it is needed to do the
       flush */
    tlb_flush_page(env, addr);
}

void helper_svm_check_intercept_param(uint32_t type, uint64_t param) {
    if (likely(!(env->hflags & HF_SVMI_MASK)))
        return;
    switch (type) {
        case SVM_EXIT_READ_CR0 ... SVM_EXIT_READ_CR0 + 8:
            if (env->intercept_cr_read & (1 << (type - SVM_EXIT_READ_CR0))) {
                helper_vmexit(type, param);
            }
            break;
        case SVM_EXIT_WRITE_CR0 ... SVM_EXIT_WRITE_CR0 + 8:
            if (env->intercept_cr_write & (1 << (type - SVM_EXIT_WRITE_CR0))) {
                helper_vmexit(type, param);
            }
            break;
        case SVM_EXIT_READ_DR0 ... SVM_EXIT_READ_DR0 + 7:
            if (env->intercept_dr_read & (1 << (type - SVM_EXIT_READ_DR0))) {
                helper_vmexit(type, param);
            }
            break;
        case SVM_EXIT_WRITE_DR0 ... SVM_EXIT_WRITE_DR0 + 7:
            if (env->intercept_dr_write & (1 << (type - SVM_EXIT_WRITE_DR0))) {
                helper_vmexit(type, param);
            }
            break;
        case SVM_EXIT_EXCP_BASE ... SVM_EXIT_EXCP_BASE + 31:
            if (env->intercept_exceptions & (1 << (type - SVM_EXIT_EXCP_BASE))) {
                helper_vmexit(type, param);
            }
            break;
        case SVM_EXIT_MSR:
            if (env->intercept & (1ULL << (SVM_EXIT_MSR - SVM_EXIT_INTR))) {
                /* FIXME: this should be read in at vmrun (faster this way?) */
                uint64_t addr = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, control.msrpm_base_pa));
                uint32_t t0, t1;
                switch ((uint32_t) ECX) {
                    case 0 ... 0x1fff:
                        t0 = (ECX * 2) % 8;
                        t1 = (ECX * 2) / 8;
                        break;
                    case 0xc0000000 ... 0xc0001fff:
                        t0 = (8192 + ECX - 0xc0000000) * 2;
                        t1 = (t0 / 8);
                        t0 %= 8;
                        break;
                    case 0xc0010000 ... 0xc0011fff:
                        t0 = (16384 + ECX - 0xc0010000) * 2;
                        t1 = (t0 / 8);
                        t0 %= 8;
                        break;
                    default:
                        helper_vmexit(type, param);
                        t0 = 0;
                        t1 = 0;
                        break;
                }
                if (ldub_phys(addr + t1) & ((1 << param) << t0))
                    helper_vmexit(type, param);
            }
            break;
        default:
            if (env->intercept & (1ULL << (type - SVM_EXIT_INTR))) {
                helper_vmexit(type, param);
            }
            break;
    }
}

void svm_check_intercept(CPUX86State *env1, uint32_t type) {
    CPUX86State *saved_env;

    saved_env = env;
    env = env1;
    helper_svm_check_intercept_param(type, 0);
    env = saved_env;
}

void helper_svm_check_io(uint32_t port, uint32_t param, uint32_t next_eip_addend) {
    if (env->intercept & (1ULL << (SVM_EXIT_IOIO - SVM_EXIT_INTR))) {
        /* FIXME: this should be read in at vmrun (faster this way?) */
        uint64_t addr = ldq_phys(env->vm_vmcb + offsetof(struct vmcb, control.iopm_base_pa));
        uint16_t mask = (1 << ((param >> 4) & 7)) - 1;
        if (lduw_phys(addr + port / 8) & (mask << (port & 7))) {
            /* next EIP */
            stq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2), env->eip + next_eip_addend);
            helper_vmexit(SVM_EXIT_IOIO, param | (port << 16));
        }
    }
}

/* Note: currently only 32 bits of exit_code are used */
void helper_vmexit(uint32_t exit_code, uint64_t exit_info_1) {
    uint32_t int_ctl;

    libcpu_log_mask(CPU_LOG_TB_IN_ASM, "vmexit(%08x, %016" PRIx64 ", %016" PRIx64 ", " TARGET_FMT_lx ")!\n", exit_code,
                    exit_info_1, ldq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2)), EIP);

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    int cpl = env->hflags & HF_CPL_MASK;
#endif

    if (env->hflags & HF_INHIBIT_IRQ_MASK) {
        stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_state), SVM_INTERRUPT_SHADOW_MASK);
        env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    } else {
        stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_state), 0);
    }

    /* Save the VM state in the vmcb */
    svm_save_seg(env->vm_vmcb + offsetof(struct vmcb, save.es), &env->segs[R_ES]);
    svm_save_seg(env->vm_vmcb + offsetof(struct vmcb, save.cs), &env->segs[R_CS]);
    svm_save_seg(env->vm_vmcb + offsetof(struct vmcb, save.ss), &env->segs[R_SS]);
    svm_save_seg(env->vm_vmcb + offsetof(struct vmcb, save.ds), &env->segs[R_DS]);

    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.gdtr.base), env->gdt.base);
    stl_phys(env->vm_vmcb + offsetof(struct vmcb, save.gdtr.limit), env->gdt.limit);

    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.idtr.base), env->idt.base);
    stl_phys(env->vm_vmcb + offsetof(struct vmcb, save.idtr.limit), env->idt.limit);

    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.efer), env->efer);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr0), env->cr[0]);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr2), env->cr[2]);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr3), env->cr[3]);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.cr4), env->cr[4]);

    int_ctl = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_ctl));
    int_ctl &= ~(V_TPR_MASK | V_IRQ_MASK);
    int_ctl |= env->v_tpr & V_TPR_MASK;
    if (env->interrupt_request & CPU_INTERRUPT_VIRQ)
        int_ctl |= V_IRQ_MASK;
    stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_ctl), int_ctl);

    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rflags), compute_eflags());
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rip), env->eip);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rsp), ESP);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.rax), EAX);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.dr7), env->dr[7]);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, save.dr6), env->dr[6]);
    stb_phys(env->vm_vmcb + offsetof(struct vmcb, save.cpl), env->hflags & HF_CPL_MASK);

    /* Reload the host state from vm_hsave */
    env->hflags2 &= ~(HF2_HIF_MASK | HF2_VINTR_MASK);
    env->hflags &= ~HF_SVMI_MASK;
    env->intercept = 0;
    env->intercept_exceptions = 0;
    env->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
    env->tsc_offset = 0;

    env->gdt.base = ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.gdtr.base));
    env->gdt.limit = ldl_phys(env->vm_hsave + offsetof(struct vmcb, save.gdtr.limit));

    env->idt.base = ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.idtr.base));
    env->idt.limit = ldl_phys(env->vm_hsave + offsetof(struct vmcb, save.idtr.limit));

    cpu_x86_update_cr0(env, ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr0)) | CR0_PE_MASK);
    cpu_x86_update_cr4(env, ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr4)));
    cpu_x86_update_cr3(env, ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.cr3)));
    /* we need to set the efer after the crs so the hidden flags get
       set properly */
    cpu_load_efer(env, ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.efer)));
    env->mflags = 0;
    load_eflags(ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.rflags)),
                ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    CC_OP_W(CC_OP_EFLAGS);

    svm_load_seg_cache(env->vm_hsave + offsetof(struct vmcb, save.es), env, R_ES);
    svm_load_seg_cache(env->vm_hsave + offsetof(struct vmcb, save.cs), env, R_CS);
    svm_load_seg_cache(env->vm_hsave + offsetof(struct vmcb, save.ss), env, R_SS);
    svm_load_seg_cache(env->vm_hsave + offsetof(struct vmcb, save.ds), env, R_DS);

    EIP = ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.rip));
    WR_se_eip(env, EIP);
    ESP_W(ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.rsp)));
    EAX_W(ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.rax)));

    env->dr[6] = ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.dr6));
    env->dr[7] = ldq_phys(env->vm_hsave + offsetof(struct vmcb, save.dr7));

    /* other setups */
    int dpl = 0;
    cpu_x86_set_cpl(env, dpl);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_code), exit_code);
    stq_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_info_1), exit_info_1);

    stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_int_info),
             ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj)));
    stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.exit_int_info_err),
             ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj_err)));
    stl_phys(env->vm_vmcb + offsetof(struct vmcb, control.event_inj), 0);

    env->hflags2 &= ~HF2_GIF_MASK;
    /* FIXME: Resets the current ASID register to zero (host ASID). */

    /* Clears the V_IRQ and V_INTR_MASKING bits inside the processor. */

    /* Clears the TSC_OFFSET inside the processor. */

    /* If the host is in PAE mode, the processor reloads the host's PDPEs
       from the page table indicated the host's CR3. If the PDPEs contain
       illegal state, the processor causes a shutdown. */

    /* Forces CR0.PE = 1, RFLAGS.VM = 0. */
    env->cr[0] |= CR0_PE_MASK;
    env->mflags &= ~VM_MASK;

    /* Disables all breakpoints in the host DR7 register. */

    /* Checks the reloaded host state for consistency. */

    /* If the host's rIP reloaded by #VMEXIT is outside the limit of the
       host's code segment or non-canonical (in the case of long mode), a
       #GP fault is delivered inside the host.) */

    /* remove any pending exception */
    env->exception_index = -1;
    env->error_code = 0;
    env->old_exception = -1;

#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (unlikely(*g_sqi.events.on_privilege_change_signals_count)) {
        g_sqi.events.on_privilege_change(cpl, dpl);
    }
#endif

    cpu_loop_exit(env);
}

/* MMX/SSE */
/* XXX: optimize by storing fptt and fptags in the static cpu state */

#define SSE_DAZ     0x0040
#define SSE_RC_MASK 0x6000
#define SSE_RC_NEAR 0x0000
#define SSE_RC_DOWN 0x2000
#define SSE_RC_UP   0x4000
#define SSE_RC_CHOP 0x6000
#define SSE_FZ      0x8000

static void update_sse_status(void) {
    int rnd_type;

    /* set rounding mode */
    switch (MXCSR & SSE_RC_MASK) {
        default:
        case SSE_RC_NEAR:
            rnd_type = float_round_nearest_even;
            break;
        case SSE_RC_DOWN:
            rnd_type = float_round_down;
            break;
        case SSE_RC_UP:
            rnd_type = float_round_up;
            break;
        case SSE_RC_CHOP:
            rnd_type = float_round_to_zero;
            break;
    }
    set_float_rounding_mode(rnd_type, &env->sse_status);

    /* set denormals are zero */
    set_flush_inputs_to_zero((MXCSR & SSE_DAZ) ? 1 : 0, &env->sse_status);

    /* set flush to zero */
    set_flush_to_zero((MXCSR & SSE_FZ) ? 1 : 0, &env->fp_status);
}

void helper_ldmxcsr(uint32_t val) {
    MXCSR_W(val);
    update_sse_status();
}

void helper_enter_mmx(void) {
    FPSTT_W(0);
    WR_cpu_dyn((uint64_t *) env->fptags, sizeof(env->fptags), 0);
}

void helper_emms(void) {
    /* set to empty state */
    WR_cpu_dyn((uint64_t *) env->fptags, sizeof(env->fptags), 0x0101010101010101ULL);
}

/* XXX: suppress */
void helper_movq(void *d, void *s) {
    *(uint64_t *) d = *(uint64_t *) s;
}

#define SHIFT 0
#include "ops_sse.h"

#define SHIFT 1
#include "ops_sse.h"

#define SHIFT 0
#include "helper_template.h"
#undef SHIFT

#define SHIFT 1
#include "helper_template.h"
#undef SHIFT

#define SHIFT 2
#include "helper_template.h"
#undef SHIFT

#ifdef TARGET_X86_64

#define SHIFT 3
#include "helper_template.h"
#undef SHIFT

#endif

/* bit operations */
target_ulong helper_bsf(target_ulong t0) {
    int count;
    target_ulong res;

    res = t0;
    count = 0;
    while ((res & 1) == 0) {
        count++;
        res >>= 1;
    }
    return count;
}

target_ulong helper_lzcnt(target_ulong t0, int wordsize) {
    int count;
    target_ulong res, mask;

    if (wordsize > 0 && t0 == 0) {
        return wordsize;
    }
    res = t0;
    count = TARGET_LONG_BITS - 1;
    mask = (target_ulong) 1 << (TARGET_LONG_BITS - 1);
    while ((res & mask) == 0) {
        count--;
        res <<= 1;
    }
    if (wordsize > 0) {
        return wordsize - 1 - count;
    }
    return count;
}

target_ulong helper_bsr(target_ulong t0) {
    return helper_lzcnt(t0, 0);
}

static int compute_all_eflags(void) {
    return CC_SRC;
}

static int compute_c_eflags(void) {
    return CC_SRC & CC_C;
}

uint32_t helper_cc_compute_all(int op) {
    switch (op) {
        default: /* should never happen */
            return 0;

        case CC_OP_EFLAGS:
            return compute_all_eflags();

        case CC_OP_MULB:
            return compute_all_mulb();
        case CC_OP_MULW:
            return compute_all_mulw();
        case CC_OP_MULL:
            return compute_all_mull();

        case CC_OP_ADDB:
            return compute_all_addb();
        case CC_OP_ADDW:
            return compute_all_addw();
        case CC_OP_ADDL:
            return compute_all_addl();

        case CC_OP_ADCB:
            return compute_all_adcb();
        case CC_OP_ADCW:
            return compute_all_adcw();
        case CC_OP_ADCL:
            return compute_all_adcl();

        case CC_OP_SUBB:
            return compute_all_subb();
        case CC_OP_SUBW:
            return compute_all_subw();
        case CC_OP_SUBL:
            return compute_all_subl();

        case CC_OP_SBBB:
            return compute_all_sbbb();
        case CC_OP_SBBW:
            return compute_all_sbbw();
        case CC_OP_SBBL:
            return compute_all_sbbl();

        case CC_OP_LOGICB:
            return compute_all_logicb();
        case CC_OP_LOGICW:
            return compute_all_logicw();
        case CC_OP_LOGICL:
            return compute_all_logicl();

        case CC_OP_INCB:
            return compute_all_incb();
        case CC_OP_INCW:
            return compute_all_incw();
        case CC_OP_INCL:
            return compute_all_incl();

        case CC_OP_DECB:
            return compute_all_decb();
        case CC_OP_DECW:
            return compute_all_decw();
        case CC_OP_DECL:
            return compute_all_decl();

        case CC_OP_SHLB:
            return compute_all_shlb();
        case CC_OP_SHLW:
            return compute_all_shlw();
        case CC_OP_SHLL:
            return compute_all_shll();

        case CC_OP_SARB:
            return compute_all_sarb();
        case CC_OP_SARW:
            return compute_all_sarw();
        case CC_OP_SARL:
            return compute_all_sarl();

#ifdef TARGET_X86_64
        case CC_OP_MULQ:
            return compute_all_mulq();

        case CC_OP_ADDQ:
            return compute_all_addq();

        case CC_OP_ADCQ:
            return compute_all_adcq();

        case CC_OP_SUBQ:
            return compute_all_subq();

        case CC_OP_SBBQ:
            return compute_all_sbbq();

        case CC_OP_LOGICQ:
            return compute_all_logicq();

        case CC_OP_INCQ:
            return compute_all_incq();

        case CC_OP_DECQ:
            return compute_all_decq();

        case CC_OP_SHLQ:
            return compute_all_shlq();

        case CC_OP_SARQ:
            return compute_all_sarq();
#endif
    }
}

uint32_t cpu_cc_compute_all(CPUX86State *env1, int op) {
    CPUX86State *saved_env;
    uint32_t ret;

    saved_env = env;
    env = env1;
    ret = helper_cc_compute_all(op);
    env = saved_env;
    return ret;
}

uint32_t helper_cc_compute_c(int op) {
    switch (op) {
        default: /* should never happen */
            return 0;

        case CC_OP_EFLAGS:
            return compute_c_eflags();

        case CC_OP_MULB:
            return compute_c_mull();
        case CC_OP_MULW:
            return compute_c_mull();
        case CC_OP_MULL:
            return compute_c_mull();

        case CC_OP_ADDB:
            return compute_c_addb();
        case CC_OP_ADDW:
            return compute_c_addw();
        case CC_OP_ADDL:
            return compute_c_addl();

        case CC_OP_ADCB:
            return compute_c_adcb();
        case CC_OP_ADCW:
            return compute_c_adcw();
        case CC_OP_ADCL:
            return compute_c_adcl();

        case CC_OP_SUBB:
            return compute_c_subb();
        case CC_OP_SUBW:
            return compute_c_subw();
        case CC_OP_SUBL:
            return compute_c_subl();

        case CC_OP_SBBB:
            return compute_c_sbbb();
        case CC_OP_SBBW:
            return compute_c_sbbw();
        case CC_OP_SBBL:
            return compute_c_sbbl();

        case CC_OP_LOGICB:
            return compute_c_logicb();
        case CC_OP_LOGICW:
            return compute_c_logicw();
        case CC_OP_LOGICL:
            return compute_c_logicl();

        case CC_OP_INCB:
            return compute_c_incl();
        case CC_OP_INCW:
            return compute_c_incl();
        case CC_OP_INCL:
            return compute_c_incl();

        case CC_OP_DECB:
            return compute_c_incl();
        case CC_OP_DECW:
            return compute_c_incl();
        case CC_OP_DECL:
            return compute_c_incl();

        case CC_OP_SHLB:
            return compute_c_shlb();
        case CC_OP_SHLW:
            return compute_c_shlw();
        case CC_OP_SHLL:
            return compute_c_shll();

        case CC_OP_SARB:
            return compute_c_sarl();
        case CC_OP_SARW:
            return compute_c_sarl();
        case CC_OP_SARL:
            return compute_c_sarl();

#ifdef TARGET_X86_64
        case CC_OP_MULQ:
            return compute_c_mull();

        case CC_OP_ADDQ:
            return compute_c_addq();

        case CC_OP_ADCQ:
            return compute_c_adcq();

        case CC_OP_SUBQ:
            return compute_c_subq();

        case CC_OP_SBBQ:
            return compute_c_sbbq();

        case CC_OP_LOGICQ:
            return compute_c_logicq();

        case CC_OP_INCQ:
            return compute_c_incl();

        case CC_OP_DECQ:
            return compute_c_incl();

        case CC_OP_SHLQ:
            return compute_c_shlq();

        case CC_OP_SARQ:
            return compute_c_sarl();
#endif
    }
}

uint64_t helper_set_cc_op_eflags(void);
uint64_t helper_set_cc_op_eflags(void) {
    WR_cpu(env, cc_src, helper_cc_compute_all(CC_OP));
    WR_cpu(env, cc_op, CC_OP_EFLAGS);
    return 0;
}

#if defined(CONFIG_SYMBEX) && defined(SYMBEX_LLVM_LIB)
void se_ensure_symbolic() {
}
#endif

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
void helper_register_symbols() {
    g_sqi.exec.helper_register_symbol("helper_load_seg", helper_load_seg);
    g_sqi.exec.helper_register_symbol("helper_iret_protected", helper_iret_protected);
}
#endif

#if defined(CONFIG_SYMBEX)
/* These are dummy functions, to be redefined by the instrumentation code */
__attribute__((weak)) void helper_se_call(target_ulong pc) {
}

__attribute__((weak)) void helper_se_ret(target_ulong pc, int retim_value) {
}
#endif

#if !defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)

#if defined(CONFIG_SYMBEX_OPCODES)
#include <s2e/opcodes.h>
#endif

void helper_se_opcode(uint64_t opcode) {
#if defined(CONFIG_SYMBEX_OPCODES)
    uint8_t opc = (opcode >> 8) & 0xFF;

    if (opc == BASE_S2E_KILL_STATE) { /* s2e_kill_state */
        char buf[512];
        target_ulong status = EAX;
        target_ulong message = EBX;

        memset(buf, 0, sizeof(buf));
        for (int count = 0; count < sizeof(buf); ++count, ++message) {
            buf[count] = cpu_ldub_kernel(env, message);
            if (buf[count] == 0)
                break;
        }

        printf("Got terminate request from guest: %s\n", buf);
        exit(status);
    }
#endif
}
#endif

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)
uint8_t RR_cpu_float_status(void *p, unsigned size) {
    CHECK_ASSERT(size == 1 && "unexpected status field width");
    return (uint8_t) __RR_env_dyn(p, size);
}

void WR_cpu_float_status(void *p, unsigned size, int v) {
    CHECK_ASSERT(size == 1 && "unexpected status field width");
    __WR_env_dyn(p, size, v);
}
#endif
