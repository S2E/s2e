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

#include "cpu-defs.h"
#include "cpu.h"

#include <tcg/tcg-op.h>

#define SIGNBIT (uint32_t) 0x80000000
#define SIGNBIT64 ((uint64_t) 1 << 63)

// SYMBEX: Keep the environment in a variable
struct CPUARMState *env = 0;

static void raise_exception(int tt) {
    env->exception_index = tt;
    cpu_loop_exit(env);
}

uint32_t HELPER(neon_tbl)(uint32_t ireg, uint32_t def, uint32_t rn, uint32_t maxindex) {
    uint32_t val;
    uint32_t tmp;
    int index;
    int shift;
    uint64_t *table;
    table = (uint64_t *) &env->vfp.regs[rn];
    val = 0;
    for (shift = 0; shift < 32; shift += 8) {
        index = (ireg >> shift) & 0xff;
        if (index < maxindex) {
            tmp = (table[index >> 3] >> ((index & 7) << 3)) & 0xff;
            val |= tmp << shift;
        } else {
            val |= def & (0xff << shift);
        }
    }
    return val;
}

#include "softmmu_exec.h"

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
#define _raw _raw_symb

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

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>

/* This will be called from S2EExecutor if running concretely; It will
   in turn call the real ARM IRQ handler with current CPUARMState.*/
uint32_t se_get_active_armv7m_external_irq(int serial) {
    return se_helper_get_active_armv7m_external_irq(env, serial);
}

void se_set_armv7m_external_irq(int irq_num) {
    se_helper_set_armv7m_external_irq(env, irq_num);
    cpu_exit(env);//exit cpu loop to invoke the interrupt immediately
}

void se_enable_all_armv7m_external_irq(int serial) {
    se_helper_enable_all_armv7m_external_irq(env, serial);
}

void se_enable_systick_irq(int mode) {
    se_helper_enable_systick_irq(env, mode);
}
void se_do_interrupt_arm(void)
{
    se_helper_do_interrupt_arm(env);
}
#endif
/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUArchState *env1, target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx, void *retaddr) {
    CPUArchState *saved_env;
    int ret;

    saved_env = env;

    if (env != env1)
        env = env1;

#ifdef CONFIG_SYMBEX
    if (unlikely(*g_sqi.events.on_tlb_miss_signals_count)) {
        g_sqi.events.on_tlb_miss(addr, is_write, retaddr);
    }
    ret = cpu_arm_handle_mmu_fault(env, page_addr, is_write, mmu_idx);
#else
    ret = cpu_arm_handle_mmu_fault(env, addr, is_write, mmu_idx);
#endif

    if (unlikely(ret)) {

#ifdef CONFIG_SYMBEX
        /* In S2E we pass page address instead of addr to cpu_arm_handle_mmu_fault,
           since the latter can be symbolic while the former is always concrete.
           To compensate, we reset fault address here. */
        if (env->exception_index == EXCP_PREFETCH_ABORT || env->exception_index == EXCP_DATA_ABORT) {
            assert(1 && "handle coprocessor exception properly");
        }
#endif

#ifdef CONFIG_SYMBEX
        if (unlikely(*g_sqi.events.on_page_fault_signals_count)) {
            g_sqi.events.on_page_fault(addr, is_write, retaddr);
        }
#endif

        raise_exception(env->exception_index);
    }
    if (saved_env != env)
        env = saved_env;
}

/* FIXME: Pass an axplicit pointer to QF to CPUARMState, and move saturating
   instructions into helper.c  */
uint32_t HELPER(add_setq)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT))
        env->QF = 1;
    return res;
}

uint32_t HELPER(add_saturate)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t) a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(sub_saturate)(uint32_t a, uint32_t b) {
    uint32_t res = a - b;
    if (((res ^ a) & SIGNBIT) && ((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t) a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(double_saturate)(int32_t val) {
    uint32_t res;
    if (val >= 0x40000000) {
        res = ~SIGNBIT;
        env->QF = 1;
    } else if (val <= (int32_t) 0xc0000000) {
        res = SIGNBIT;
        env->QF = 1;
    } else {
        res = val << 1;
    }
    return res;
}

uint32_t HELPER(add_usaturate)(uint32_t a, uint32_t b) {
    uint32_t res = a + b;
    if (res < a) {
        env->QF = 1;
        res = ~0;
    }
    return res;
}

uint32_t HELPER(sub_usaturate)(uint32_t a, uint32_t b) {
    uint32_t res = a - b;
    if (res > a) {
        env->QF = 1;
        res = 0;
    }
    return res;
}

/* Signed saturation.  */
static inline uint32_t do_ssat(int32_t val, int shift) {
    int32_t top;
    uint32_t mask;

    top = val >> shift;
    mask = (1u << shift) - 1;
    if (top > 0) {
        env->QF = 1;
        return mask;
    } else if (top < -1) {
        env->QF = 1;
        return ~mask;
    }
    return val;
}

/* Unsigned saturation.  */
static inline uint32_t do_usat(int32_t val, int shift) {
    uint32_t max;

    max = (1u << shift) - 1;
    if (val < 0) {
        env->QF = 1;
        return 0;
    } else if (val > max) {
        env->QF = 1;
        return max;
    }
    return val;
}

/* Signed saturate.  */
uint32_t HELPER(ssat)(uint32_t x, uint32_t shift) {
    return do_ssat(x, shift);
}

/* Dual halfword signed saturate.  */
uint32_t HELPER(ssat16)(uint32_t x, uint32_t shift) {
    uint32_t res;

    res = (uint16_t) do_ssat((int16_t) x, shift);
    res |= do_ssat(((int32_t) x) >> 16, shift) << 16;
    return res;
}

/* Unsigned saturate.  */
uint32_t HELPER(usat)(uint32_t x, uint32_t shift) {
    return do_usat(x, shift);
}

/* Dual halfword unsigned saturate.  */
uint32_t HELPER(usat16)(uint32_t x, uint32_t shift) {
    uint32_t res;

    res = (uint16_t) do_usat((int16_t) x, shift);
    res |= do_usat(((int32_t) x) >> 16, shift) << 16;
    return res;
}

/* Sign/zero extend */
uint32_t HELPER(sxtb16)(uint32_t x) {
    uint32_t res;
    res = (uint16_t)(int8_t) x;
    res |= (uint32_t)(int8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(uxtb16)(uint32_t x) {
    uint32_t res;
    res = (uint16_t)(uint8_t) x;
    res |= (uint32_t)(uint8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(clz)(uint32_t x) {
    uint32_t res;
    res = (uint32_t) clz32(x);
    return res;
}

int32_t HELPER(sdiv)(int32_t num, int32_t den) {
    if (den == 0)
        return 0;
    if (num == INT_MIN && den == -1)
        return INT_MIN;
    return num / den;
}

uint32_t HELPER(udiv)(uint32_t num, uint32_t den) {
    if (den == 0)
        return 0;
    return num / den;
}

uint32_t HELPER(rbit)(uint32_t x) {
    x = ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
    x = ((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4);
    x = ((x & 0x88888888) >> 3) | ((x & 0x44444444) >> 1) | ((x & 0x22222222) << 1) | ((x & 0x11111111) << 3);
    return x;
}

uint32_t HELPER(abs)(uint32_t x) {
    return ((int32_t) x < 0) ? -x : x;
}

void HELPER(wfi)(void) {
    env->exception_index = EXCP_HLT;
    env->halted = 1;
    cpu_loop_exit(env);
}

void HELPER(exception)(uint32_t excp) {
    env->exception_index = excp;
    cpu_loop_exit(env);
}

uint32_t HELPER(cpsr_read)(CPUARMState *env) {
    return cpsr_read(env) & ~CPSR_EXEC;
}

void HELPER(cpsr_write)(CPUARMState *env, uint32_t val, uint32_t mask) {
    cpsr_write(env, val, mask);
}

/* Access to user mode registers from privileged modes.  */
uint32_t HELPER(get_user_reg)(CPUARMState *env, uint32_t regno) {
    uint32_t val;

    if (regno == 13) {
        val = RR_cpu(env, banked_r13[0]);
    } else if (regno == 14) {
        val = RR_cpu(env, banked_r14[0]);
    } else if (regno == 15) {
        val = env->regs[regno];
    } else if (regno >= 8 && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        val = RR_cpu(env, usr_regs[regno - 8]);
    } else {
        val = RR_cpu(env, regs[regno]);
    }
    return val;
}

void HELPER(set_user_reg)(CPUARMState *env, uint32_t regno, uint32_t val) {
    if (regno == 13) {
        WR_cpu(env, banked_r13[0], val);
    } else if (regno == 14) {
        WR_cpu(env, banked_r14[0], val);
    } else if (regno == 15) {
        env->regs[regno] = val;
    } else if (regno >= 8 && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        WR_cpu(env, usr_regs[regno - 8], val);
    } else {
        WR_cpu(env, regs[regno], val);
    }
}

/* ??? Flag setting arithmetic is awkward because we need to do comparisons.
   The only way to do that in TCG is a conditional branch, which clobbers
   all our temporaries.  For now implement these as helper functions.  */

uint32_t HELPER(add_cc)(CPUARMState *env, uint32_t a, uint32_t b) {
    uint32_t result;
    result = a + b;
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    WR_cpu(env, CF, (result < a));
    WR_cpu(env, VF, ((a ^ b ^ -1) & (a ^ result)));
    return result;
}

uint32_t HELPER(adc_cc)(CPUARMState *env, uint32_t a, uint32_t b) {
    uint32_t result;
    if (!(RR_cpu(env, CF))) {
        result = a + b;
        WR_cpu(env, CF, (result < a));
    } else {
        result = a + b + 1;
        WR_cpu(env, CF, (result <= a));
    }
    WR_cpu(env, VF, ((a ^ b ^ -1) & (a ^ result)));
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    return result;
}

uint32_t HELPER(sub_cc)(CPUARMState *env, uint32_t a, uint32_t b) {
    uint32_t result;
    result = a - b;
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    WR_cpu(env, CF, (a >= b));
    WR_cpu(env, VF, ((a ^ b) & (a ^ result)));
    return result;
}

uint32_t HELPER(sbc_cc)(CPUARMState *env, uint32_t a, uint32_t b) {
    uint32_t result;
    if (!(RR_cpu(env, CF))) {
        result = a - b - 1;
        WR_cpu(env, CF, (a > b));
    } else {
        result = a - b;
        WR_cpu(env, CF, (a >= b));
    }
    WR_cpu(env, VF, ((a ^ b) & (a ^ result)));
    WR_cpu(env, NF, result);
    WR_cpu(env, ZF, result);
    return result;
}

/* Similarly for variable shift instructions.  */

uint32_t HELPER(shl)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return x << shift;
}

uint32_t HELPER(shr)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return (uint32_t) x >> shift;
}

uint32_t HELPER(sar)(uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32)
        shift = 31;
    return (int32_t) x >> shift;
}

uint32_t HELPER(shl_cc)(CPUARMState *env, uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env, CF, (x & 1));
        else
            WR_cpu(env, CF, 0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (32 - shift)) & 1));
        return x << shift;
    }
    return x;
}

uint32_t HELPER(shr_cc)(CPUARMState *env, uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env, CF, ((x >> 31) & 1));
        else
            WR_cpu(env, CF, 0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return x >> shift;
    }
    return x;
}

uint32_t HELPER(sar_cc)(CPUARMState *env, uint32_t x, uint32_t i) {
    int shift = i & 0xff;
    if (shift >= 32) {
        WR_cpu(env, CF, ((x >> 31) & 1));
        return (int32_t) x >> 31;
    } else if (shift != 0) {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return (int32_t) x >> shift;
    }
    return x;
}

uint32_t HELPER(ror_cc)(CPUARMState *env, uint32_t x, uint32_t i) {
    int shift1, shift;
    shift1 = i & 0xff;
    shift = shift1 & 0x1f;
    if (shift == 0) {
        if (shift1 != 0)
            WR_cpu(env, CF, ((x >> 31) & 1));
        return x;
    } else {
        WR_cpu(env, CF, ((x >> (shift - 1)) & 1));
        return ((uint32_t) x >> shift) | (x << (32 - shift));
    }
}
