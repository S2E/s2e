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
#include <tcg/utils/log.h>
#include <utils/atomic.h>
#include "cpu.h"
#include "exec-tb.h"

#include "accel/tb-hash.h"

#include <cpu/accel/cpu-ops.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#if defined(CONFIG_SYMBEX_MP)
#include "tcg/tcg-llvm.h"
#endif

int tb_invalidated_flag;

#ifdef CONFIG_SYMBEX
static int tb_invalidate_before_fetch = 0;

void se_tb_safe_flush(void) {
    tb_invalidate_before_fetch = 1;
}
#endif

// #define CONFIG_DEBUG_EXEC

/* exit the current TB, but without causing any exception to be raised */
void cpu_loop_exit_noexc(CPUState *cpu) {
    cpu->exception_index = -1;
    cpu_loop_exit(cpu);
}

void cpu_loop_exit(CPUState *cpu) {
    siglongjmp(cpu->jmp_env, 1);
}

void cpu_loop_exit_restore(CPUState *cpu, uintptr_t ra) {
    if (ra) {
        cpu_restore_state(cpu, ra);
    }

    cpu_loop_exit(cpu);
}

static TranslationBlock *tb_find_slow(CPUArchState *env, target_ulong pc, target_ulong cs_base, uint64_t flags,
                                      uint32_t cflags) {
    TranslationBlock *tb, **ptb1;
    unsigned int h;
    tb_page_addr_t phys_pc, phys_page1;

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
        if (env_cpu(env)->generate_llvm && !tb->llvm_function) {
            llvm_nok = 1;
        }
#endif

        if (tb->pc == pc && tb_page_addr0(tb) == phys_page1 && tb->cs_base == cs_base && tb->flags == flags &&
            !llvm_nok) {
            goto found;
        }
        ptb1 = &tb->phys_hash_next;
    }
not_found:
    /* if no translated code available, then translate it now */
    tb = tb_gen_code(env, pc, cs_base, flags, cflags);

found:
    /* Move the last found TB to the head of the list */
    if (likely(*ptb1)) {
        *ptb1 = tb->phys_hash_next;
        tb->phys_hash_next = tb_phys_hash[h];
        tb_phys_hash[h] = tb;
    }
    /* we add the TB in the virtual pc hash table */
    CPUJumpCache *jc = env_cpu(env)->tb_jmp_cache;
    h = tb_jmp_cache_hash_func(pc);
    jc->array[h].pc = pc;
    qatomic_set(&jc->array[h].tb, tb);
    return tb;
}

static inline TranslationBlock *tb_find_fast(CPUArchState *env) {
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;

/**
 * Plugin code cannot usually invalidate the TB cache safely
 * because it would also detroy the currently running code.
 * Instead, flush the cache at the next TB fetch.
 */
#ifdef CONFIG_SYMBEX
    if (tb_invalidate_before_fetch) {
        tb_invalidate_before_fetch = 0;
        tb_flush(cpu);
    }
#endif

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    TCGTBCPUState s = cpu->cc->tcg_ops->get_tb_cpu_state(cpu);

    /* A request for specific cflags applies to the next TB only. It takes effect
       when this lookup generates a TB, because cflags are not part of the key of
       the lookup. */
    uint32_t cflags = cpu->cflags_next_tb == -1 ? 0 : cpu->cflags_next_tb;
    cpu->cflags_next_tb = -1;

    tb = qatomic_read(&cpu->tb_jmp_cache->array[tb_jmp_cache_hash_func(s.pc)].tb);

#ifdef CONFIG_SYMBEX
    int llvm_nok = cpu->generate_llvm && (!tb || !tb->llvm_function);
#else
    int llvm_nok = 0;
#endif

    if (unlikely(!tb || tb->pc != s.pc || tb->cs_base != s.cs_base || tb->flags != s.flags || llvm_nok)) {
        tb = tb_find_slow(env, s.pc, s.cs_base, s.flags, cflags);
    }
    return tb;
}

static void cpu_handle_debug_exception(CPUState *cpu) {
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH (wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }
    if (tcg_ops->debug_excp_handler) {
        tcg_ops->debug_excp_handler(cpu);
    }
}

/*****************************************************************/

/* main execution loop */

static uintptr_t se_tb_exec(CPUState *cpu, TranslationBlock *tb);

static uintptr_t fetch_and_run_tb(TranslationBlock *prev_tb, int tb_exit_code, CPUArchState *env) {
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb = tb_find_fast(env);

    libcpu_log_mask(CPU_LOG_EXEC, "fetch_and_run_tb cs:eip=%#lx:%#lx e=%#lx fl=%lx riw=%d\n",
                    (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) env->eip + tb->size,
                    (uint64_t) env->mflags, env->kvm_request_interrupt_window);

    if (tb_invalidated_flag) {
        prev_tb = NULL;
        tb_invalidated_flag = 0;
    }

    libcpu_log_mask(CPU_LOG_EXEC, "Trace 0x%08lx [%016" PRIx64 "]\n", (long) tb->tc.ptr, tb->pc);

    /*
     * see if we can patch the calling TB. When the TB
     * spans two pages, we cannot safely do a direct jump.
     */
    if (prev_tb && tb_page_addr1(tb) == -1) {
        tb_add_jump(prev_tb, tb_exit_code, tb);
    }

    /* cpu_exit() might be called while translating the TB, but before it is
       linked into a potentially infinite loop. Avoid starting execution if
       there is a pending exit request. */
    barrier();
    if (unlikely(cpu->exit_request)) {
        return 0;
    }

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
    assert(env->eip == env->precise_eip);
#endif

    /* execute the generated code */
    return se_tb_exec(cpu, tb);
}

static bool process_interrupt_request(CPUArchState *env) {
    CPUState *cpu = env_cpu(env);
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
    int interrupt_request = cpu->interrupt_request;

    if (likely(!interrupt_request)) {
        return false;
    }

    bool has_interrupt = false;

    if (interrupt_request & CPU_INTERRUPT_DEBUG) {
        cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
        cpu->exception_index = EXCP_DEBUG;
        cpu_loop_exit(cpu);
    }

    if (interrupt_request & CPU_INTERRUPT_RESET) {
        tcg_ops->cpu_exec_reset(cpu);
        cpu_loop_exit(cpu);
    }

    if (unlikely(cpu->singlestep_flags & SSTEP_NOIRQ)) {
        /* Mask out external interrupts for this step. */
        interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
    }

    /* Ensure that no TB jump will be modified as the program flow was
       changed. */
    if (tcg_ops->cpu_exec_interrupt(cpu, interrupt_request)) {
        has_interrupt = true;
    }

    /* Don't use the cached interrupt_request value,
          do_interrupt may have updated the EXITTB flag. */
    if (cpu->interrupt_request & CPU_INTERRUPT_EXITTB) {
        cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
        has_interrupt = true;
    }

    return has_interrupt;
}

static int process_exceptions(CPUArchState *env) {
    CPUState *cpu = env_cpu(env);
    int ret = 0;

    if (cpu->exception_index < 0) {
        return ret;
    }

    /* if an exception is pending, we execute it here */
    if (cpu->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        ret = cpu->exception_index;
        if (ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(cpu);
        }
    } else {
        libcpu_log_mask(CPU_LOG_INT, "  do_interrupt exidx=%x\n", cpu->exception_index);
        cpu->cc->tcg_ops->do_interrupt(cpu);
        cpu->exception_index = -1;
    }

    return ret;
}

static bool execution_loop(CPUArchState *env) {
    CPUState *cpu = env_cpu(env);
    uintptr_t last_tb = 0;
    int last_tb_exit_code = 0;
    TranslationBlock *ltb = NULL;

    for (;;) {
        bool has_interrupt = false;

        /* Clear the interrupt flag now since we're processing
         * cpu->interrupt_request and cpu->exit_request.
         * Ensure zeroing happens before reading cpu->exit_request or
         * cpu->interrupt_request (see also store-release in
         * tcg_kick_vcpu_thread())
         *
         * S2E: libcpu has no tcg_kick_vcpu_thread(), cpu_exit() does that
         * store-release.
         */
        qatomic_set_mb(&cpu->neg.icount_decr.u16.high, 0);

        if (process_interrupt_request(env)) {
            // Ensure that no TB jump will be modified as
            // the program flow was changed
            ltb = NULL;
            has_interrupt = true;
        }

        if (unlikely(!has_interrupt && cpu->exit_request)) {
            libcpu_log_mask(CPU_LOG_EXEC, "  execution_loop: exit_request\n");
            cpu->exit_request = 0;
            cpu->exception_index = EXCP_INTERRUPT;

            // XXX: return status code instead
            cpu_loop_exit(cpu);
        }

#if defined(DEBUG_DISAS) || defined(CONFIG_DEBUG_EXEC)
        if (libcpu_loglevel_mask(CPU_LOG_TB_CPU)) {
#if defined(TARGET_I386)
            // It's too heavy to log all cpu state, usually gp regs are enough
            // TODO: add an option to customize which regs to print
            log_cpu_state(cpu, X86_DUMP_GPREGS);
#endif
        }
#endif /* DEBUG_DISAS || CONFIG_DEBUG_EXEC */

        last_tb = fetch_and_run_tb(ltb, last_tb_exit_code, env);

        last_tb_exit_code = last_tb & TB_EXIT_MASK;
        ltb = (TranslationBlock *) (last_tb & ~TB_EXIT_MASK);

        if (ltb) {
            libcpu_log_mask(CPU_LOG_EXEC, "ltb s=%#lx e=%#lx fl=%lx exit_code=%x riw=%d\n", (uint64_t) ltb->pc,
                            (uint64_t) ltb->pc + ltb->size, (uint64_t) env->mflags, last_tb_exit_code,
                            env->kvm_request_interrupt_window);
        }

        if (last_tb_exit_code > TB_EXIT_IDXMAX) {
            cpu->cc->tcg_ops->synchronize_from_tb(cpu, ltb);
            ltb = NULL;
        }

        /* The window is closed during an interrupt shadow, it opens after the next instruction */
        if (env->kvm_request_interrupt_window && (env->mflags & IF_MASK) && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
            env->kvm_request_interrupt_window = 0;
            return true;
        }
    }

    return false;
}

int cpu_exec(CPUState *cpu) {
    CPUArchState *env = cpu_env(cpu);
    int ret;

    if (cpu->halted) {
        if (!cpu->cc->tcg_ops->cpu_exec_halt(cpu)) {
            return EXCP_HALTED;
        }

        cpu->halted = 0;
    }

#ifdef CONFIG_SYMBEX
    if (!g_sqi.exec.is_runnable()) {
        if (g_sqi.exec.is_yielded())
            g_sqi.exec.reset_state_switch_timer();
        return EXCP_SE;
    }
#endif

    libcpu_log_mask(CPU_LOG_EXEC, "cpu_loop enter mflags=%#lx hf1=%#x hf2=%#x\n", (uint64_t) env->mflags, env->hflags,
                    env->hflags2);

    /* prepare setjmp context for exception handling */
    for (;;) {
        if (sigsetjmp(cpu->jmp_env, 0) == 0) {
            libcpu_log_mask(CPU_LOG_EXEC, "  setjmp entered eip=%#lx\n", (uint64_t) env->eip);

#ifdef CONFIG_SYMBEX
            assert(cpu->exception_index != EXCP_SE);
            if (g_sqi.exec.finalize_tb_exec()) {
                g_sqi.exec.cleanup_tb_exec();
                if (cpu->exception_index == EXCP_SE) {
                    return EXCP_SE;
                }
                continue;
            }
#endif

            ret = process_exceptions(env);
            if (ret) {
                break;
            }

            if (execution_loop(env)) {
                break;
            }
        } else {
#ifdef CONFIG_SYMBEX
            g_sqi.exec.cleanup_tb_exec();
            if (!g_sqi.exec.is_runnable()) {
                return EXCP_SE;
            }
#endif
            /* env and cpu are not modified after setjmp(), so they keep their
               values after longjmp(). */
        }
    } /* for(;;) */
    libcpu_log_mask(CPU_LOG_EXEC, "cpu_loop exit ret=%#x eip=%#lx\n", ret, (uint64_t) env->eip);

    cpu->cc->tcg_ops->cpu_exec_exit(cpu);

    return ret;
}

#include "s2e/cpu-exec-symbex.c.inc"
