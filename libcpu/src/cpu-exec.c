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

#include <cpu/config.h>
#include <cpu/types.h>
#include <tcg/tcg.h>
#include "cpu.h"
#include "exec-tb.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

// #define DEBUG_EXEC
// #define TRACE_EXEC

#ifdef DEBUG_EXEC
#define DPRINTF(...) fprintf(logfile, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#if defined(CONFIG_SYMBEX_MP)
#include "tcg/tcg-llvm.h"
#endif

int tb_invalidated_flag;

struct cpu_stats_t g_cpu_stats;

#ifdef CONFIG_SYMBEX
static int tb_invalidate_before_fetch = 0;

void se_tb_safe_flush(void) {
    tb_invalidate_before_fetch = 1;
}
#endif

//#define CONFIG_DEBUG_EXEC

void cpu_loop_exit(CPUArchState *env) {
    env->current_tb = NULL;
    longjmp(env->jmp_env, 1);
}

void cpu_loop_exit_restore(CPUArchState *env, uintptr_t ra) {
    if (ra) {
        cpu_restore_state(env, ra);
    }

    cpu_loop_exit(env);
}

/* exit the current TB from a signal handler. The host registers are
   restored in a state compatible with the CPU emulator
 */
#if defined(CONFIG_SOFTMMU)
void cpu_resume_from_signal(CPUArchState *env, void *puc) {
    /* XXX: restore cpu registers saved in host registers */

    env->exception_index = -1;
    longjmp(env->jmp_env, 1);
}
#endif

static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc, target_ulong cs_base, uint64_t flags) {
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;
    target_ulong virt_page2;

    tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
    phys_pc = get_page_addr_code(env, pc);
    phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_phys_hash_func(phys_pc);
    ptb1 = &tb_phys_hash[h];
    for (;;) {
        tb = *ptb1;
        if (!tb) {
            goto not_found;
        }

        int llvm_nok = 0;
#if defined(CONFIG_SYMBEX_MP)
        if (env->generate_llvm && !tb->llvm_function) {
            llvm_nok = 1;
        }
#endif

        if (tb->pc == pc && tb->page_addr[0] == phys_page1 && tb->cs_base == cs_base && tb->flags == flags &&
            !llvm_nok) {
            /* check next page if needed */
            if (tb->page_addr[1] != -1) {
                tb_page_addr_t phys_page2;

                virt_page2 = (pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
                phys_page2 = get_page_addr_code(env, virt_page2);
                if (tb->page_addr[1] == phys_page2) {
                    ++g_cpu_stats.tb_misses;
                }
                goto found;
            } else {
                ++g_cpu_stats.tb_misses;
                goto found;
            }
        }
        ptb1 = &tb->phys_hash_next;
    }
not_found:
    /* if no translated code available, then translate it now */
    tb = tb_gen_code(env, pc, cs_base, flags, 0);
    ++g_cpu_stats.tb_regens;

found:
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tb_phys_hash[h];
        tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUArchState *env) {
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    int flags;

/**
 * Plugin code cannot usually invalidate the TB cache safely
 * because it would also detroy the currently running code.
 * Instead, flush the cache at the next TB fetch.
 */
#ifdef CONFIG_SYMBEX
    if (tb_invalidate_before_fetch) {
        tb_invalidate_before_fetch = 0;
        tb_flush(env);
    }
#endif

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];

#ifdef CONFIG_SYMBEX
    int llvm_nok = env->generate_llvm && (!tb || !tb->llvm_function);
#else
    int llvm_nok = 0;
#endif

    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base || tb->flags != flags || llvm_nok)) {
        tb = tb_find_slow(env, pc, cs_base, flags);
    } else {
        ++g_cpu_stats.tb_hits;
    }
    return tb;
}

static CPUDebugExcpHandler *debug_excp_handler;

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler) {
    CPUDebugExcpHandler *old_handler = debug_excp_handler;

    debug_excp_handler = handler;
    return old_handler;
}

static void cpu_handle_debug_exception(CPUArchState *env) {
    CPUWatchpoint *wp;

    if (!env->watchpoint_hit) {
        QTAILQ_FOREACH (wp, &env->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }
    if (debug_excp_handler) {
        debug_excp_handler(env);
    }
}

/*****************************************************************/

/* main execution loop */

// volatile sig_atomic_t exit_request;

#ifdef TRACE_EXEC
static void dump_regs(CPUX86State *env, int isStart) {
#if defined(CONFIG_SYMBEX)
    target_ulong eax, ebx, ecx, edx, esi, edi, ebp, esp;
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EAX]), (uint8_t *) &eax, sizeof(eax));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EBX]), (uint8_t *) &ebx, sizeof(ebx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ECX]), (uint8_t *) &ecx, sizeof(ecx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EDX]), (uint8_t *) &edx, sizeof(edx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ESI]), (uint8_t *) &esi, sizeof(esi));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EDI]), (uint8_t *) &edi, sizeof(edi));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EBP]), (uint8_t *) &ebp, sizeof(ebp));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ESP]), (uint8_t *) &esp, sizeof(esp));

    fprintf(logfile, "%c cs:eip=%lx:%lx eax=%lx ebx=%lx ecx=%lx edx=%lx esi=%lx edi=%lx ebp=%lx ss:esp=%lx:%lx\n",
            isStart ? 's' : 'e', (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) eax,
            (uint64_t) ebx, (uint64_t) ecx, (uint64_t) edx, (uint64_t) esi, (uint64_t) edi, (uint64_t) ebp,
            (uint64_t) env->segs[R_SS].selector, (uint64_t) esp);
#else
    fprintf(logfile, "%c cs:eip=%lx:%lx eax=%lx ebx=%lx ecx=%lx edx=%lx esi=%lx edi=%lx ebp=%lx ss:esp=%lx:%lx\n",
            isStart ? 's' : 'e', (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) env->regs[R_EAX],
            (uint64_t) env->regs[R_EBX], (uint64_t) env->regs[R_ECX], (uint64_t) env->regs[R_EDX],
            (uint64_t) env->regs[R_ESI], (uint64_t) env->regs[R_EDI], (uint64_t) env->regs[R_EBP],
            (uint64_t) env->segs[R_SS].selector, (uint64_t) env->regs[R_ESP]);
#endif
}
#endif

static uintptr_t fetch_and_run_tb(TranslationBlock *prev_tb, int tb_exit_code, CPUArchState *env) {
    uint8_t *tc_ptr;
    uintptr_t last_tb;

    TranslationBlock *tb = tb_find_fast(env);

    DPRINTF("fetch_and_run_tb cs:eip=%#lx:%#lx e=%#lx fl=%lx riw=%d\n", (uint64_t) env->segs[R_CS].selector,
            (uint64_t) env->eip, (uint64_t) env->eip + tb->size, (uint64_t) env->mflags,
            env->kvm_request_interrupt_window);

    if (tb_invalidated_flag) {
        prev_tb = NULL;
        tb_invalidated_flag = 0;
    }

#ifdef CONFIG_DEBUG_EXEC
    libcpu_log_mask(CPU_LOG_EXEC, "Trace 0x%08lx [" TARGET_FMT_lx "] %s\n", (long) tb->tc_ptr, tb->pc,
                    lookup_symbol(tb->pc));
#endif
    /*
     * see if we can patch the calling TB. When the TB
     * spans two pages, we cannot safely do a direct jump.
     */
    if (prev_tb && tb->page_addr[1] == -1) {
        tb_add_jump(prev_tb, tb_exit_code, tb);
    }

    /* cpu_interrupt might be called while translating the
       TB, but before it is linked into a potentially
       infinite loop and becomes env->current_tb. Avoid
       starting execution if there is a pending interrupt. */

    env->current_tb = tb;

    env->translate_single_instruction = 0;

    barrier();
    if (unlikely(env->exit_request)) {
        env->current_tb = NULL;
        return 0;
    }

    tc_ptr = tb->tc.ptr;
#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
    assert(env->eip == env->precise_eip);
#endif

    /* execute the generated code */

#ifdef TRACE_EXEC
    dump_regs(env, 1);
#endif

#if defined(CONFIG_SYMBEX)
    env->se_current_tb = tb;
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        **g_sqi.mode.running_exception_emulation_code = 0;
        last_tb = tcg_qemu_tb_exec(env, tc_ptr);
    } else {
        last_tb = g_sqi.exec.tb_exec(env, tb);
    }
    env->se_current_tb = NULL;
#else

    last_tb = tcg_qemu_tb_exec(env, tc_ptr);

#endif

#ifdef TRACE_EXEC
    dump_regs(env, 0);
#endif

    env->current_tb = NULL;

    return last_tb;
}

static bool process_interrupt_request(CPUArchState *env) {
    int interrupt_request = env->interrupt_request;

    if (likely(!interrupt_request)) {
        return false;
    }

    bool has_interrupt = false;

    DPRINTF("  process_interrupt intrq=%#x mflags=%#lx hf1=%#x hf2=%#x\n", interrupt_request, (uint64_t) env->mflags,
            env->hflags, env->hflags2);

    if (unlikely(env->singlestep_enabled & SSTEP_NOIRQ)) {
        /* Mask out external interrupts for this step. */
        interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
    }
    if (interrupt_request & CPU_INTERRUPT_DEBUG) {
        env->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
        env->exception_index = EXCP_DEBUG;
        cpu_loop_exit(env);
    }

    if (interrupt_request & CPU_INTERRUPT_INIT) {
        svm_check_intercept(env, SVM_EXIT_INIT);
        do_cpu_init(env);
        env->exception_index = EXCP_HALTED;
        cpu_loop_exit(env);
    } else if (interrupt_request & CPU_INTERRUPT_SIPI) {
        perror("Not implemented");
    } else if (env->hflags2 & HF2_GIF_MASK) {
        if ((interrupt_request & CPU_INTERRUPT_SMI) && !(env->hflags & HF_SMM_MASK)) {
            svm_check_intercept(env, SVM_EXIT_SMI);
            env->interrupt_request &= ~CPU_INTERRUPT_SMI;
            do_smm_enter(env);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_NMI) && !(env->hflags2 & HF2_NMI_MASK)) {
            env->interrupt_request &= ~CPU_INTERRUPT_NMI;
            env->hflags2 |= HF2_NMI_MASK;
            do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
            has_interrupt = true;
        } else if (interrupt_request & CPU_INTERRUPT_MCE) {
            env->interrupt_request &= ~CPU_INTERRUPT_MCE;
            do_interrupt_x86_hardirq(env, EXCP12_MCHK, 0);
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_HARD) &&
                   (((env->hflags2 & HF2_VINTR_MASK) && (env->hflags2 & HF2_HIF_MASK)) ||
                    (!(env->hflags2 & HF2_VINTR_MASK) &&
                     (env->mflags & IF_MASK && !(env->hflags & HF_INHIBIT_IRQ_MASK))))) {
            int intno;
            svm_check_intercept(env, SVM_EXIT_INTR);
            env->interrupt_request &= ~(CPU_INTERRUPT_HARD | CPU_INTERRUPT_VIRQ);
            intno = env->kvm_irq;
            env->kvm_irq = -1;

            libcpu_log_mask(CPU_LOG_INT, "Servicing hardware INT=0x%02x\n", intno);
            if (intno >= 0) {
#ifdef SE_KVM_DEBUG_IRQ
                DPRINTF("Handling interrupt %d\n", intno);
#endif

                do_interrupt_x86_hardirq(env, intno, 1);
            }

            /* ensure that no TB jump will be modified as
                   the program flow was changed */
            has_interrupt = true;
        } else if ((interrupt_request & CPU_INTERRUPT_VIRQ) && (env->mflags & IF_MASK) &&
                   !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
            int intno;
            /* FIXME: this should respect TPR */
            svm_check_intercept(env, SVM_EXIT_VINTR);
            intno = ldl_phys(env->vm_vmcb + offsetof(struct vmcb, control.int_vector));
            libcpu_log_mask(CPU_LOG_TB_IN_ASM, "Servicing virtual hardware INT=0x%02x\n", intno);
            do_interrupt_x86_hardirq(env, intno, 1);
            env->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
            has_interrupt = true;
        }
    }

    /* Don't use the cached interrupt_request value,
          do_interrupt may have updated the EXITTB flag. */
    if (env->interrupt_request & CPU_INTERRUPT_EXITTB) {
        env->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
        has_interrupt = true;
    }

    return has_interrupt;
}

static int process_exceptions(CPUArchState *env) {
    int ret = 0;

    if (env->exception_index < 0) {
        return ret;
    }

    /* if an exception is pending, we execute it here */
    if (env->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        ret = env->exception_index;
        if (ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(env);
        }
    } else {
        DPRINTF("  do_interrupt exidx=%x\n", env->exception_index);
        do_interrupt(env);
        env->exception_index = -1;
    }

    return ret;
}

static bool execution_loop(CPUArchState *env) {
    uintptr_t last_tb = 0;
    int last_tb_exit_code = 0;
    TranslationBlock *ltb = NULL;

    for (;;) {
        bool has_interrupt = false;
        if (process_interrupt_request(env)) {
            // Ensure that no TB jump will be modified as
            // the program flow was changed
            ltb = NULL;
            has_interrupt = true;
        }

        if (unlikely(!has_interrupt && env->exit_request)) {
            DPRINTF("  execution_loop: exit_request\n");
            env->exit_request = 0;
            env->exception_index = EXCP_INTERRUPT;

            // XXX: return status code instead
            cpu_loop_exit(env);
        }

        env->exit_request = 0;

#if defined(DEBUG_DISAS) || defined(CONFIG_DEBUG_EXEC)
        if (libcpu_loglevel_mask(CPU_LOG_TB_CPU)) {
#if defined(TARGET_I386)
            // It's too heavy to log all cpu state, usually gp regs are enough
            // TODO: add an option to customize which regs to print
            log_cpu_state(env, X86_DUMP_GPREGS);
#endif
        }
#endif /* DEBUG_DISAS || CONFIG_DEBUG_EXEC */

        last_tb = fetch_and_run_tb(ltb, last_tb_exit_code, env);

        last_tb_exit_code = last_tb & TB_EXIT_MASK;
        ltb = (TranslationBlock *) (last_tb & ~TB_EXIT_MASK);

        if (ltb) {
            DPRINTF("ltb s=%#lx e=%#lx fl=%lx exit_code=%x riw=%d\n", (uint64_t) ltb->pc,
                    (uint64_t) ltb->pc + ltb->size, (uint64_t) env->mflags, last_tb_exit_code,
                    env->kvm_request_interrupt_window);
        }

        if (last_tb_exit_code > TB_EXIT_IDXMAX) {
            env->eip = ltb->pc - ltb->cs_base;
            ltb = NULL;
        }

        if (env->kvm_request_interrupt_window && (env->mflags & IF_MASK)) {
            env->kvm_request_interrupt_window = 0;
            return true;
        }
    }

    return false;
}

int cpu_exec(CPUArchState *env) {
    int ret;

    if (env->halted) {
        if (!cpu_has_work(env)) {
            return EXCP_HALTED;
        }

        env->halted = 0;
    }

    cpu_single_env = env;

#ifdef CONFIG_SYMBEX
    if (!g_sqi.exec.is_runnable()) {
        if (g_sqi.exec.is_yielded())
            g_sqi.exec.reset_state_switch_timer();
        return EXCP_SE;
    }
#endif

    env->exception_index = -1;

    DPRINTF("cpu_loop enter mflags=%#lx hf1=%#x hf2=%#x\n", (uint64_t) env->mflags, env->hflags, env->hflags2);

    /* prepare setjmp context for exception handling */
    for (;;) {
        if (setjmp(env->jmp_env) == 0) {
            /**
             * It is important to reset the current TB everywhere where the CPU loop exits.
             * Otherwise, TB unchaining might get stuck on the next signal.
             * This usually happens when TB cache is flushed but current tb is not reset.
             */
            env->current_tb = NULL;

            DPRINTF("  setjmp entered eip=%#lx\n", (uint64_t) env->eip);

#ifdef CONFIG_SYMBEX
            assert(env->exception_index != EXCP_SE);
            if (g_sqi.exec.finalize_tb_exec()) {
                g_sqi.exec.cleanup_tb_exec();
                if (env->exception_index == EXCP_SE) {
                    cpu_single_env = NULL;
                    env->current_tb = NULL;
                    return EXCP_SE;
                }
                continue;
            }
#endif

            ret = process_exceptions(env);
            if (ret) {
                if (ret == EXCP_HLT && env->interrupt_request) {
                    env->exception_index = -1;
                    env->halted = 0;
                    continue;
                }
                break;
            }

            if (execution_loop(env)) {
                break;
            }
        } else {
#ifdef CONFIG_SYMBEX
            g_sqi.exec.cleanup_tb_exec();
            if (!g_sqi.exec.is_runnable()) {
                cpu_single_env = NULL;
                env->current_tb = NULL;
                return EXCP_SE;
            }
#endif

            /* Reload env after longjmp - the compiler may have smashed all
             * local variables as longjmp is marked 'noreturn'. */
            env = cpu_single_env;
        }
    } /* for(;;) */
    DPRINTF("cpu_loop exit ret=%#x eip=%#lx\n", ret, (uint64_t) env->eip);

    env->current_tb = NULL;

#if defined(TARGET_I386)
#ifdef CONFIG_SYMBEX
    g_sqi.regs.set_cc_op_eflags(env);
#else
    /* restore flags in standard format */
    WR_cpu(env, cc_src, cpu_cc_compute_all(env, CC_OP));
    WR_cpu(env, cc_op, CC_OP_EFLAGS);
    // WR_cpu(env, eflags, RR_cpu(env, eflags) |
    //       helper_cc_compute_all(CC_OP) | (DF & DF_MASK));
    /* restore flags in standard format */
    // env->eflags = env->eflags | cpu_cc_compute_all(env, CC_OP)
    //    | (DF & DF_MASK);

    /* This mask corresponds to bits that must be 0 in eflags */
    assert(((env->mflags | env->cc_src) & 0xffc08028) == 0);
#endif

#elif defined(TARGET_ARM)
/* XXX: Save/restore host fpu exception state?.  */
#elif defined(TARGET_UNICORE32)
#elif defined(TARGET_SPARC)
#elif defined(TARGET_PPC)
#elif defined(TARGET_LM32)
#elif defined(TARGET_M68K)
    cpu_m68k_flush_flags(env, env->cc_op);
    env->cc_op = CC_OP_FLAGS;
    env->sr = (env->sr & 0xffe0) | env->cc_dest | (env->cc_x << 4);
#elif defined(TARGET_MICROBLAZE)
#elif defined(TARGET_MIPS)
#elif defined(TARGET_SH4)
#elif defined(TARGET_ALPHA)
#elif defined(TARGET_CRIS)
#elif defined(TARGET_S390X)
#elif defined(TARGET_XTENSA)
/* XXXXX */
#else
#error unsupported target CPU
#endif

    env->current_tb = NULL;

    /* fail safe : never use cpu_single_env outside cpu_exec() */
    cpu_single_env = NULL;
    return ret;
}
