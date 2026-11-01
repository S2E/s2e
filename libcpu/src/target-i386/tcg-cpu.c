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

/// @file
/// The x86 implementation of TCGCPUOps, the interface through which the CPU
/// loop and the softmmu call into the target.
///
/// This file is compiled natively only. KLEE never reads the table because it
/// is not registered as a KLEE object, so the softmmu hooks that the bitcode
/// also needs stay in op_helper.c.

#include <cpu/config.h>
#include <cpu/types.h>
#include <tcg/utils/log.h>
#include "cpu.h"

#include <cpu/accel/cpu-ops.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

static TCGTBCPUState x86_get_tb_cpu_state(CPUState *cs) {
    CPUX86State *env = cpu_env(cs);
    target_ulong cs_base = env->segs[R_CS].base;
    target_ulong pc = cs_base + env->eip;

    return (TCGTBCPUState) {
        .pc = pc,
        .flags = env->hflags | (env->mflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK)),
        .cs_base = cs_base,
    };
}

static void x86_cpu_synchronize_from_tb(CPUState *cs, const TranslationBlock *tb) {
    cpu_env(cs)->eip = tb->pc - tb->cs_base;
}

static void x86_restore_state_to_opc(CPUState *cs, const TranslationBlock *tb, const uint64_t *data) {
    CPUX86State *env = cpu_env(cs);
    int cc_op = data[1];
    env->eip = data[0] - tb->cs_base;

    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }

    if (libcpu_loglevel_mask(CPU_LOG_EXEC)) {
        libcpu_log("restored state: eip=%#" PRIx64 " cc_op=%#x", (uint64_t) env->eip, cc_op);
    }
}

/* Restores the flags in the standard format. */
static void x86_cpu_exec_exit(CPUState *cs) {
    CPUX86State *env = cpu_env(cs);

#ifdef CONFIG_SYMBEX
    /* set_cc_op_eflags() can execute a helper in the current state, and a
       yielded or zombie state must not run any more code. */
    if (!g_sqi.exec.is_runnable()) {
        return;
    }

    g_sqi.regs.set_cc_op_eflags(env);
#else
    WR_cpu(env, cc_src, cpu_cc_compute_all(env, CC_OP));
    WR_cpu(env, cc_op, CC_OP_EFLAGS);

    /* This mask corresponds to bits that must be 0 in eflags */
    assert(((env->mflags | env->cc_src) & 0xffc08028) == 0);
#endif
}

static void x86_cpu_do_interrupt(CPUState *cs) {
    do_interrupt(cpu_env(cs));
}

/* Returns true when the program flow changed, in which case the caller must
   not chain the previous TB to the next one. */
static bool x86_cpu_exec_interrupt(CPUState *cs, int interrupt_request) {
    CPUX86State *env = cpu_env(cs);
    bool has_interrupt = false;

    libcpu_log_mask(CPU_LOG_INT, "  process_interrupt intrq=%#x mflags=%#lx hf1=%#x hf2=%#x\n", interrupt_request,
                    (uint64_t) env->mflags, env->hflags, env->hflags2);

    if (interrupt_request & CPU_INTERRUPT_SIPI) {
        perror("Not implemented");
    } else if (env->hflags2 & HF2_GIF_MASK) {
        if ((interrupt_request & CPU_INTERRUPT_SMI) && !(env->hflags & HF_SMM_MASK)) {
            svm_check_intercept(env, SVM_EXIT_SMI);
            cs->interrupt_request &= ~CPU_INTERRUPT_SMI;
            do_smm_enter(env);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_NMI) && !(env->hflags2 & HF2_NMI_MASK)) {
            cs->interrupt_request &= ~CPU_INTERRUPT_NMI;
            env->hflags2 |= HF2_NMI_MASK;
            do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
            has_interrupt = true;
        } else if (interrupt_request & CPU_INTERRUPT_MCE) {
            cs->interrupt_request &= ~CPU_INTERRUPT_MCE;
            do_interrupt_x86_hardirq(env, EXCP12_MCHK, 0);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_HARD) &&
                   (((env->hflags2 & HF2_VINTR_MASK) && (env->hflags2 & HF2_HIF_MASK)) ||
                    (!(env->hflags2 & HF2_VINTR_MASK) &&
                     (env->mflags & IF_MASK && !(env->hflags & HF_INHIBIT_IRQ_MASK))))) {
            int intno;

            svm_check_intercept(env, SVM_EXIT_INTR);
            cs->interrupt_request &= ~CPU_INTERRUPT_VIRQ;

            /* This clears the request of the source that supplies the vector.
               The request of the other source stays pending. */
            intno = cpu_get_pic_interrupt(env);
            assert(intno >= 0);

            libcpu_log_mask(CPU_LOG_INT, "Servicing hardware INT=%d\n", intno);
            if (intno >= 0) {
                libcpu_log_mask(CPU_LOG_INT, "Handling interrupt INT=%d\n", intno);
                do_interrupt_x86_hardirq(env, intno, 1);
            }

            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_VIRQ) && (env->mflags & IF_MASK) &&
                   !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
            int intno;
            /* FIXME: this should respect TPR */
            svm_check_intercept(env, SVM_EXIT_VINTR);
            intno = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_vector));
            libcpu_log_mask(CPU_LOG_TB_IN_ASM, "Servicing virtual hardware INT=0x%02x\n", intno);
            do_interrupt_x86_hardirq(env, intno, 1);
            cs->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
            has_interrupt = true;
        }
    }

    return has_interrupt;
}

static bool x86_cpu_exec_halt(CPUState *cs) {
    return cpu_has_work(cpu_env(cs));
}

/* Handles CPU_INTERRUPT_RESET, which is CPU_INTERRUPT_INIT on x86. The caller
   leaves the CPU loop through exception_index. */
static void x86_cpu_exec_reset(CPUState *cs) {
    CPUX86State *env = cpu_env(cs);

    svm_check_intercept(env, SVM_EXIT_INIT);
    do_cpu_init(env);
    cs->exception_index = EXCP_HALTED;
}

/* The RF flag disables all architectural breakpoints. */
static bool x86_debug_check_breakpoint(CPUState *cs) {
    return !(cpu_env(cs)->mflags & RF_MASK);
}

static int x86_cpu_mmu_index(CPUState *cs, bool ifetch) {
    return x86_mmu_index(cpu_env(cs));
}

static const TCGCPUOps s_x86_tcg_ops = {
    .precise_smc = true,
    /* S2E: upstream drops the store-to-load barrier with
       TCG_MO_ALL & ~TCG_MO_ST_LD. That changes the generated code, so it is
       left for a separate change. */
    .guest_default_memory_order = TCG_MO_ALL,
    .initialize = optimize_flags_init,
    .get_tb_cpu_state = x86_get_tb_cpu_state,
    .synchronize_from_tb = x86_cpu_synchronize_from_tb,
    .restore_state_to_opc = x86_restore_state_to_opc,
    .mmu_index = x86_cpu_mmu_index,
    .cpu_exec_exit = x86_cpu_exec_exit,
    .tlb_fill = x86_cpu_tlb_fill,
    .pointer_wrap = x86_cpu_pointer_wrap,
    .do_interrupt = x86_cpu_do_interrupt,
    .cpu_exec_halt = x86_cpu_exec_halt,
    .cpu_exec_interrupt = x86_cpu_exec_interrupt,
    .cpu_exec_reset = x86_cpu_exec_reset,
    .do_unaligned_access = x86_cpu_do_unaligned_access,
    .debug_excp_handler = breakpoint_handler,
    .debug_check_breakpoint = x86_debug_check_breakpoint,
};

static void x86_cpu_set_pc(CPUState *cs, vaddr value) {
    cpu_env(cs)->eip = value;
}

static vaddr x86_cpu_get_pc(CPUState *cs) {
    CPUX86State *env = cpu_env(cs);

    /* Match x86_get_tb_cpu_state(). */
    return env->eip + env->segs[R_CS].base;
}

const CPUClass g_x86_cpu_class = {
    .tcg_ops = &s_x86_tcg_ops,
    .set_pc = x86_cpu_set_pc,
    .get_pc = x86_cpu_get_pc,
};
