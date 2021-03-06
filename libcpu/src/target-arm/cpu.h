/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017  Adrian Herrera
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

#ifndef CPU_ARM_H
#define CPU_ARM_H

#include <assert.h>

#include <cpu/common.h>
#include <cpu/interrupt.h>
#include <cpu/tb.h>
#include <cpu/types.h>
#include <libcpu-log.h>

#include "cpu-defs.h"
#include "nvic_interfaces.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include <cpu/arm/cpu.h>

#define EXCP_UDEF 1 /* undefined instruction */
#define EXCP_SWI 2  /* software interrupt */
#define EXCP_PREFETCH_ABORT 3
#define EXCP_DATA_ABORT 4
#define EXCP_IRQ 5
#define EXCP_FIQ 6
#define EXCP_BKPT 7
#define EXCP_EXCEPTION_EXIT 8 /* Return from v7M exception.  */
#define EXCP_KERNEL_TRAP 9    /* Jumped to kernel code page.  */
#define EXCP_STREX 10

#define ARMV7M_EXCP_RESET 1
#define ARMV7M_EXCP_NMI 2
#define ARMV7M_EXCP_HARD 3
#define ARMV7M_EXCP_MEM 4
#define ARMV7M_EXCP_BUS 5
#define ARMV7M_EXCP_USAGE 6
#define ARMV7M_EXCP_SVC 11
#define ARMV7M_EXCP_DEBUG 12
#define ARMV7M_EXCP_PENDSV 14
#define ARMV7M_EXCP_SYSTICK 15

/* ARM-specific interrupt pending bits.  */
#define CPU_INTERRUPT_FIQ CPU_INTERRUPT_TGT_EXT_1

struct arm_boot_info;

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)

/* uncomment this to compile assertions in */
/* #define DO_SANITY_CHECK */

#ifdef DO_SANITY_CHECK
#define CHECK_ASSERT(x) assert(x)
#else
#define CHECK_ASSERT(x)
#endif

/* Macros to access registers */
static inline target_ulong __RR_env_raw(CPUARMState *cpuState, unsigned offset, unsigned size) {
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        switch (size) {
            case 1:
                return *((uint8_t *) cpuState + offset);
            case 2:
                return *(uint16_t *) ((uint8_t *) cpuState + offset);
            case 4:
                return *(uint32_t *) ((uint8_t *) cpuState + offset);
            case 8:
                return *(uint64_t *) ((uint8_t *) cpuState + offset);
            default:
                assert(false);
                return 0;
        }
    } else {
        target_ulong result = 0;
        g_sqi.regs.read_concrete(offset, (uint8_t *) &result, size);

        return result;
    }
}

static inline void __WR_env_raw(CPUARMState *cpuState, unsigned offset, target_ulong value, unsigned size) {
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        switch (size) {
            case 1:
                *((uint8_t *) cpuState + offset) = value;
                break;
            case 2:
                *(uint16_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            case 4:
                *(uint32_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            case 8:
                *(uint64_t *) ((uint8_t *) cpuState + offset) = value;
                break;
            default:
                assert(false);
        }
    } else {
        g_sqi.regs.write_concrete(offset, (uint8_t *) &value, size);
    }
}

#define RR_cpu(cpu, reg) ((__typeof__(cpu->reg)) __RR_env_raw(cpu, offsetof(CPUARMState, reg), sizeof(cpu->reg)))
#define WR_cpu(cpu, reg, value) __WR_env_raw(cpu, offsetof(CPUARMState, reg), (target_ulong) value, sizeof(cpu->reg))
#else /* defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) */
#define RR_cpu(cpu, reg) cpu->reg
#define WR_cpu(cpu, reg, value) cpu->reg = value
#endif /* defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB) */

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
#define WR_se_pc(cpu, value) cpu->preceise_pc = value
#else
#define WR_se_pc(cpu, value)
#endif

CPUARMState *cpu_arm_init(const char *cpu_model);
void arm_translate_init(void);
int cpu_arm_exec(CPUARMState *s);
void do_interrupt(CPUARMState *);
void switch_mode(CPUARMState *, int);
uint32_t do_arm_semihosting(CPUARMState *env);

/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_arm_signal_handler(int host_signum, void *pinfo, void *puc);
int cpu_arm_handle_mmu_fault(CPUARMState *env, target_ulong address, int rw, int mmu_idx);
#define cpu_handle_mmu_fault cpu_arm_handle_mmu_fault

static inline void cpu_set_tls(CPUARMState *env, target_ulong newtls) {
    env->cp15.c13_tls2 = newtls;
}

/* #define CPSR_M (0x1f) */
// #define CPSR_T (1 << 5)
// #define CPSR_F (1 << 6)
// #define CPSR_I (1 << 7)
// #define CPSR_A (1 << 8)
// #define CPSR_E (1 << 9)
// #define CPSR_IT_2_7 (0xfc00)
// #define CPSR_GE (0xf << 16)
// #define CPSR_RESERVED (0xf << 20)
// #define CPSR_J (1 << 24)
// #define CPSR_IT_0_1 (3 << 25)
// #define CPSR_Q (1 << 27)
// #define CPSR_V (1 << 28)
// #define CPSR_C (1 << 29)
// #define CPSR_Z (1 << 30)
// #define CPSR_N (1 << 31)
// #define CPSR_NZCV (CPSR_N | CPSR_Z | CPSR_C | CPSR_V)

// #define CPSR_IT (CPSR_IT_0_1 | CPSR_IT_2_7)
// #define CACHED_CPSR_BITS (CPSR_T | CPSR_GE | CPSR_IT | CPSR_Q | CPSR_NZCV)
// [> Bits writable in user mode.  <]
// #define CPSR_USER (CPSR_NZCV | CPSR_Q | CPSR_GE)
// [> Execution state bits.  MRS read as zero, MSR writes ignored.  <]
/* #define CPSR_EXEC (CPSR_T | CPSR_IT | CPSR_J) */

/* Return the current CPSR value.  */
uint32_t cpsr_read(CPUARMState *env);
/* Set the CPSR.  Note that some bits of mask must be all-set or all-clear.  */
void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask);

/* Return the current xPSR value.  */
static inline uint32_t xpsr_read(CPUARMState *env) {
    int ZF;
    ZF = (RR_cpu(env, ZF) == 0);
    return (RR_cpu(env, NF) & 0x80000000) | (ZF << 30) | (RR_cpu(env, CF) << 29) |
           ((RR_cpu(env, VF) & 0x80000000) >> 3) | (env->QF << 27) | (env->thumb << 24) |
           ((env->condexec_bits & 3) << 25) | ((env->condexec_bits & 0xfc) << 8) | env->v7m.exception;
}

/* Set the xPSR.  Note that some bits of mask must be all-set or all-clear.  */
static inline void xpsr_write(CPUARMState *env, uint32_t val, uint32_t mask) {
//sync var exception for kvm env by using hard-code offset
    unsigned long *armcpu;
    uint32_t *exception;
    armcpu = env->nvic+0x308;
    exception = (unsigned long)(*armcpu+0x8b50);

    if (mask & CPSR_NZCV) {
        WR_cpu(env, ZF, (~val) & CPSR_Z);
        WR_cpu(env, NF, val);
        WR_cpu(env, CF, (val >> 29) & 1);
        WR_cpu(env, VF, (val << 3) & 0x80000000);
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & (1 << 24))
        env->thumb = ((val & (1 << 24)) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & 0x1ff) {
        env->v7m.exception = val & 0x1ff;
        *exception = val & 0x1ff;
    }
}

/* Return the current FPSCR value.  */
uint32_t vfp_get_fpscr(CPUARMState *env);
void vfp_set_fpscr(CPUARMState *env, uint32_t val);

/* enum arm_cpu_mode { */
// ARM_CPU_MODE_USR = 0x10,
// ARM_CPU_MODE_FIQ = 0x11,
// ARM_CPU_MODE_IRQ = 0x12,
// ARM_CPU_MODE_SVC = 0x13,
// ARM_CPU_MODE_ABT = 0x17,
// ARM_CPU_MODE_UND = 0x1b,
// ARM_CPU_MODE_SYS = 0x1f
/* }; */

/* VFP system registers.  */
#define ARM_VFP_FPSID 0
#define ARM_VFP_FPSCR 1
#define ARM_VFP_MVFR1 6
#define ARM_VFP_MVFR0 7
#define ARM_VFP_FPEXC 8
#define ARM_VFP_FPINST 9
#define ARM_VFP_FPINST2 10

/* iwMMXt coprocessor control registers.  */
#define ARM_IWMMXT_wCID 0
#define ARM_IWMMXT_wCon 1
#define ARM_IWMMXT_wCSSF 2
#define ARM_IWMMXT_wCASF 3
#define ARM_IWMMXT_wCGR0 8
#define ARM_IWMMXT_wCGR1 9
#define ARM_IWMMXT_wCGR2 10
#define ARM_IWMMXT_wCGR3 11

/* enum arm_features { */
// ARM_FEATURE_VFP,
// ARM_FEATURE_AUXCR,  [> ARM1026 Auxiliary control register.  <]
// ARM_FEATURE_XSCALE, [> Intel XScale extensions.  <]
// ARM_FEATURE_IWMMXT, [> Intel iwMMXt extension.  <]
// ARM_FEATURE_V6,
// ARM_FEATURE_V6K,
// ARM_FEATURE_V7,
// ARM_FEATURE_THUMB2,
// ARM_FEATURE_MPU, [> Only has Memory Protection Unit, not full MMU.  <]
// ARM_FEATURE_VFP3,
// ARM_FEATURE_VFP_FP16,
// ARM_FEATURE_NEON,
// ARM_FEATURE_THUMB_DIV, [> divide supported in Thumb encoding <]
// ARM_FEATURE_M,         [> Microcontroller profile.  <]
// ARM_FEATURE_OMAPCP,    [> OMAP specific CP15 ops handling.  <]
// ARM_FEATURE_THUMB2EE,
// ARM_FEATURE_V7MP, [> v7 Multiprocessing Extensions <]
// ARM_FEATURE_V4T,
// ARM_FEATURE_V5,
// ARM_FEATURE_STRONGARM,
// ARM_FEATURE_VAPA,    [> cp15 VA to PA lookups <]
// ARM_FEATURE_ARM_DIV, [> divide supported in ARM encoding <]
// ARM_FEATURE_VFP4,    [> VFPv4 (implies that NEON is v2) <]
// ARM_FEATURE_GENERIC_TIMER,
// ARM_FEATURE_MVFR, [> Media and VFP Feature Registers 0 and 1 <]
/* }; */
enum arm_features {
    ARM_FEATURE_VFP,
    ARM_FEATURE_AUXCR,  /* ARM1026 Auxiliary control register.  */
    ARM_FEATURE_XSCALE, /* Intel XScale extensions.  */
    ARM_FEATURE_IWMMXT, /* Intel iwMMXt extension.  */
    ARM_FEATURE_V6,
    ARM_FEATURE_V6K,
    ARM_FEATURE_V7,
    ARM_FEATURE_THUMB2,
    ARM_FEATURE_MPU, /* Only has Memory Protection Unit, not full MMU.  */
    ARM_FEATURE_VFP3,
    ARM_FEATURE_VFP_FP16,
    ARM_FEATURE_NEON,
    ARM_FEATURE_THUMB_DIV, /* divide supported in Thumb encoding */
    ARM_FEATURE_M,         /* Microcontroller profile.  */
    ARM_FEATURE_OMAPCP,    /* OMAP specific CP15 ops handling.  */
    ARM_FEATURE_THUMB2EE,
    ARM_FEATURE_V7MP, /* v7 Multiprocessing Extensions */
    ARM_FEATURE_V7VE, /* v7 Virtualization Extensions (non-EL2 parts) */
    ARM_FEATURE_V4T,
    ARM_FEATURE_V5,
    ARM_FEATURE_STRONGARM,
    ARM_FEATURE_VAPA,    /* cp15 VA to PA lookups */
    ARM_FEATURE_ARM_DIV, /* divide supported in ARM encoding */
    ARM_FEATURE_VFP4,    /* VFPv4 (implies that NEON is v2) */
    ARM_FEATURE_GENERIC_TIMER,
    ARM_FEATURE_MVFR,             /* Media and VFP Feature Registers 0 and 1 */
    ARM_FEATURE_DUMMY_C15_REGS,   /* RAZ/WI all of cp15 crn=15 */
    ARM_FEATURE_CACHE_TEST_CLEAN, /* 926/1026 style test-and-clean ops */
    ARM_FEATURE_CACHE_DIRTY_REG,  /* 1136/1176 cache dirty status register */
    ARM_FEATURE_CACHE_BLOCK_OPS,  /* v6 optional cache block operations */
    ARM_FEATURE_MPIDR,            /* has cp15 MPIDR */
    ARM_FEATURE_PXN,              /* has Privileged Execute Never bit */
    ARM_FEATURE_LPAE,             /* has Large Physical Address Extension */
    ARM_FEATURE_V8,
    ARM_FEATURE_AARCH64,    /* supports 64 bit mode */
    ARM_FEATURE_V8_AES,     /* implements AES part of v8 Crypto Extensions */
    ARM_FEATURE_CBAR,       /* has cp15 CBAR */
    ARM_FEATURE_CRC,        /* ARMv8 CRC instructions */
    ARM_FEATURE_CBAR_RO,    /* has cp15 CBAR and it is read-only */
    ARM_FEATURE_EL2,        /* has EL2 Virtualization support */
    ARM_FEATURE_EL3,        /* has EL3 Secure monitor support */
    ARM_FEATURE_V8_SHA1,    /* implements SHA1 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_SHA256,  /* implements SHA256 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_PMULL,   /* implements PMULL part of v8 Crypto Extensions */
    ARM_FEATURE_THUMB_DSP,  /* DSP insns supported in the Thumb encodings */
    ARM_FEATURE_PMU,        /* has PMU support */
    ARM_FEATURE_VBAR,       /* has cp15 VBAR */
    ARM_FEATURE_M_SECURITY, /* M profile Security Extension */
    ARM_FEATURE_JAZELLE,    /* has (trivial) Jazelle implementation */
    ARM_FEATURE_SVE,        /* has Scalable Vector Extension */
    ARM_FEATURE_V8_SHA512,  /* implements SHA512 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_SHA3,    /* implements SHA3 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_SM3,     /* implements SM3 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_SM4,     /* implements SM4 part of v8 Crypto Extensions */
    ARM_FEATURE_V8_ATOMICS, /* ARMv8.1-Atomics feature */
    ARM_FEATURE_V8_RDM,     /* implements v8.1 simd round multiply */
    ARM_FEATURE_V8_DOTPROD, /* implements v8.2 simd dot product */
    ARM_FEATURE_V8_FP16,    /* implements v8.2 half-precision float */
    ARM_FEATURE_V8_FCMA,    /* has complex number part of v8.3 extensions.  */
    ARM_FEATURE_M_MAIN,     /* M profile Main Extension */
};
static inline int arm_feature(CPUARMState *env, int feature) {
    return (env->features & (1ULL << feature)) != 0;
}

void arm_cpu_list(FILE *f, fprintf_function cpu_fprintf);

/* Interface between CPU and Interrupt controller.  */
/* void armv7m_nvic_set_pending(void *opaque, int irq, bool secure); */
// int armv7m_nvic_acknowledge_irq(void *opaque);
/* void armv7m_nvic_complete_irq(void *opaque, int irq, bool secure); */

void cpu_arm_set_cp_io(CPUARMState *env, int cpnum, ARMReadCPFunc *cp_read, ARMWriteCPFunc *cp_write, void *opaque);

/* Does the core conform to the the "MicroController" profile. e.g. Cortex-M3.
   Note the M in older cores (eg. ARM7TDMI) stands for Multiply. These are
   conventional cores (ie. Application or Realtime profile).  */

#define IS_M(env) arm_feature(env, ARM_FEATURE_M)
#define ARM_CPUID(env) (env->cp15.c0_cpuid)

#define ARM_CPUID_ARM1026 0x4106a262
#define ARM_CPUID_ARM926 0x41069265
#define ARM_CPUID_ARM946 0x41059461
#define ARM_CPUID_TI915T 0x54029152
#define ARM_CPUID_TI925T 0x54029252
#define ARM_CPUID_SA1100 0x4401A11B
#define ARM_CPUID_SA1110 0x6901B119
#define ARM_CPUID_PXA250 0x69052100
#define ARM_CPUID_PXA255 0x69052d00
#define ARM_CPUID_PXA260 0x69052903
#define ARM_CPUID_PXA261 0x69052d05
#define ARM_CPUID_PXA262 0x69052d06
#define ARM_CPUID_PXA270 0x69054110
#define ARM_CPUID_PXA270_A0 0x69054110
#define ARM_CPUID_PXA270_A1 0x69054111
#define ARM_CPUID_PXA270_B0 0x69054112
#define ARM_CPUID_PXA270_B1 0x69054113
#define ARM_CPUID_PXA270_C0 0x69054114
#define ARM_CPUID_PXA270_C5 0x69054117
#define ARM_CPUID_ARM1136 0x4117b363
#define ARM_CPUID_ARM1136_R2 0x4107b362
#define ARM_CPUID_ARM1176 0x410fb767
#define ARM_CPUID_ARM11MPCORE 0x410fb022
#define ARM_CPUID_CORTEXA8 0x410fc080
#define ARM_CPUID_CORTEXA9 0x410fc090
#define ARM_CPUID_CORTEXA15 0x412fc0f1
#define ARM_CPUID_CORTEXM3 0x410fc231
#define ARM_CPUID_ANY 0xffffffff

#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32

#define cpu_init cpu_arm_init
#define cpu_exec cpu_arm_exec
#define cpu_gen_code cpu_arm_gen_code
#define cpu_signal_handler cpu_arm_signal_handler
#define cpu_list arm_cpu_list

#define CPU_SAVE_VERSION 6

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _kernel
#define MMU_MODE1_SUFFIX _user
#define MMU_USER_IDX 1

/* static inline int cpu_mmu_index(CPUARMState *env) { */
// return (env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_USR ? 1 : 0;
// }

#include "cpu-all.h"

/* Bit usage in the TB flags field: */
#define ARM_TBFLAG_THUMB_SHIFT 0
#define ARM_TBFLAG_THUMB_MASK (1 << ARM_TBFLAG_THUMB_SHIFT)
#define ARM_TBFLAG_VECLEN_SHIFT 1
#define ARM_TBFLAG_VECLEN_MASK (0x7 << ARM_TBFLAG_VECLEN_SHIFT)
#define ARM_TBFLAG_VECSTRIDE_SHIFT 4
#define ARM_TBFLAG_VECSTRIDE_MASK (0x3 << ARM_TBFLAG_VECSTRIDE_SHIFT)
#define ARM_TBFLAG_PRIV_SHIFT 6
#define ARM_TBFLAG_PRIV_MASK (1 << ARM_TBFLAG_PRIV_SHIFT)
#define ARM_TBFLAG_VFPEN_SHIFT 7
#define ARM_TBFLAG_VFPEN_MASK (1 << ARM_TBFLAG_VFPEN_SHIFT)
#define ARM_TBFLAG_CONDEXEC_SHIFT 8
#define ARM_TBFLAG_CONDEXEC_MASK (0xff << ARM_TBFLAG_CONDEXEC_SHIFT)
#define ARM_TBFLAG_BSWAP_CODE_SHIFT 16
#define ARM_TBFLAG_BSWAP_CODE_MASK (1 << ARM_TBFLAG_BSWAP_CODE_SHIFT)
/* Bits 31..17 are currently unused. */

/* some convenience accessor macros */
#define ARM_TBFLAG_THUMB(F) (((F) &ARM_TBFLAG_THUMB_MASK) >> ARM_TBFLAG_THUMB_SHIFT)
#define ARM_TBFLAG_VECLEN(F) (((F) &ARM_TBFLAG_VECLEN_MASK) >> ARM_TBFLAG_VECLEN_SHIFT)
#define ARM_TBFLAG_VECSTRIDE(F) (((F) &ARM_TBFLAG_VECSTRIDE_MASK) >> ARM_TBFLAG_VECSTRIDE_SHIFT)
#define ARM_TBFLAG_PRIV(F) (((F) &ARM_TBFLAG_PRIV_MASK) >> ARM_TBFLAG_PRIV_SHIFT)
#define ARM_TBFLAG_VFPEN(F) (((F) &ARM_TBFLAG_VFPEN_MASK) >> ARM_TBFLAG_VFPEN_SHIFT)
#define ARM_TBFLAG_CONDEXEC(F) (((F) &ARM_TBFLAG_CONDEXEC_MASK) >> ARM_TBFLAG_CONDEXEC_SHIFT)
#define ARM_TBFLAG_BSWAP_CODE(F) (((F) &ARM_TBFLAG_BSWAP_CODE_MASK) >> ARM_TBFLAG_BSWAP_CODE_SHIFT)

static inline void cpu_get_tb_cpu_state(CPUARMState *env, target_ulong *pc, target_ulong *cs_base, int *flags) {
    int privmode;
    *pc = env->regs[15];
    *cs_base = 0;
    *flags = (env->thumb << ARM_TBFLAG_THUMB_SHIFT) | (env->vfp.vec_len << ARM_TBFLAG_VECLEN_SHIFT) |
             (env->vfp.vec_stride << ARM_TBFLAG_VECSTRIDE_SHIFT) | (env->condexec_bits << ARM_TBFLAG_CONDEXEC_SHIFT) |
             (env->bswap_code << ARM_TBFLAG_BSWAP_CODE_SHIFT);
    if (arm_feature(env, ARM_FEATURE_M)) {
        privmode = !((env->v7m.exception == 0) && (env->v7m.control & 1));
    } else {
        privmode = (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR;
    }
    if (privmode) {
        *flags |= ARM_TBFLAG_PRIV_MASK;
    }
    if (env->vfp.xregs[ARM_VFP_FPEXC] & (1 << 30)) {
        *flags |= ARM_TBFLAG_VFPEN_MASK;
    }
}

static inline bool cpu_has_work(CPUARMState *env) {
    return env->interrupt_request & (CPU_INTERRUPT_FIQ | CPU_INTERRUPT_HARD | CPU_INTERRUPT_EXITTB);
}

#include "exec-all.h"

static inline void cpu_pc_from_tb(CPUARMState *env, TranslationBlock *tb) {
    env->regs[15] = tb->pc;
}
/* Load an instruction and return it in the standard little-endian order */
/*
static inline uint32_t arm_ldl_code(uint32_t addr, bool do_swap)
{
    uint32_t insn = ldl_code(addr);
    if (do_swap) {
        return bswap32(insn);
    }
    return insn;
}
*/
/* Ditto, for a halfword (Thumb) instruction */
/*
static inline uint16_t arm_lduw_code(uint32_t addr, bool do_swap)
{
    uint16_t insn = lduw_code(addr);
    if (do_swap) {
        return bswap16(insn);
    }
    return insn;
}
*/
#endif
