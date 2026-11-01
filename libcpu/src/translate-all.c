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

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>

#include <cpu/config.h>
#include <cpu/disas.h>
#include <cpu/precise-pc.h>
#include <cpu/tlb.h>
#include <cpu/types.h>

#define NO_CPU_IO_DEFS
#include <tcg/insn-start-words.h>
#include <tcg/tcg.h>
#include "cpu.h"
#include "timer.h"

#if defined(CONFIG_SYMBEX_MP)
#include <tcg/tcg-llvm.h>
#endif

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include "accel/tlb-bounds.h"
#include "exec-tb.h"
#include "exec.h"

#include <cpu/accel/cpu-ops.h>

/*
 * Isolate the portion of code gen which can setjmp/longjmp.
 * Return the size of the generated code, or negative on error.
 */
static int setjmp_gen_code(TCGContext *tcg_ctx, CPUArchState *env, TranslationBlock *tb, int *max_insns) {
    int ret = sigsetjmp(tcg_ctx->jmp_trans, 0);
    if (unlikely(ret != 0)) {
        return ret;
    }

    tcg_func_start(tcg_ctx);

    tb->cflags &= ~CF_COUNT_MASK;
    tb->cflags |= (*max_insns & CF_COUNT_MASK);
    gen_intermediate_code(env, tb);
    assert(tb->size != 0);
    *max_insns = tb->icount;

    return tcg_gen_code(tcg_ctx, tb, tb->pc);
}

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb) {
    TCGContext *s = tcg_ctx;
    void *gen_code_buf;
    int gen_code_size;
    int max_insns = tb->cflags & CF_COUNT_MASK;

    if (max_insns == 0) {
        max_insns = TCG_MAX_INSNS;
    }
    QEMU_BUILD_BUG_ON(CF_COUNT_MASK + 1 != TCG_MAX_INSNS);

    //    tb->tc.ptr = tcg_ctx->code_gen_ptr;
    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;

    tcg_ctx->gen_tb = tb;
    tcg_ctx->guest_mo = env_cpu(env)->cc->tcg_ops->guest_default_memory_order;

tb_overflow:
    gen_code_size = setjmp_gen_code(s, env, tb, &max_insns);
    if (unlikely(gen_code_size < 0)) {
        switch (gen_code_size) {
            case -1:
                /*
                 * Overflow of code_gen_buffer, or the current slice of it.
                 *
                 * TODO: We don't need to re-do gen_intermediate_code, nor
                 * should we re-do the tcg optimization currently hidden
                 * inside tcg_gen_code.  All that should be required is to
                 * flush the TBs, allocate a new TB, re-initialize it per
                 * above, and re-do the actual code generation.
                 */
                tcg_ctx->gen_tb = NULL;
                return -1;

            case -2:
                /*
                 * The code generated for the TranslationBlock is too large.
                 * The maximum size allowed by the unwind info is 64k.
                 * There may be stricter constraints from relocations
                 * in the tcg backend.
                 *
                 * Try again with half as many insns as we attempted this time.
                 * If a single insn overflows, there's a bug somewhere...
                 */
                assert(max_insns > 1);
                max_insns /= 2;

#ifdef CONFIG_SYMBEX
                tb->se_tb = g_sqi.tb.tb_alloc();
#endif

                goto tb_overflow;

            default:
                g_assert_not_reached();
        }
    }

    tcg_ctx->gen_tb = NULL;

    /* generate machine code */
    gen_code_buf = tcg_splitwx_to_rw(tb->tc.ptr);

    if (libcpu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        libcpu_log("----------------\n");
        libcpu_log("OUT %#" PRIx64 " - cs:eip=%#" PRIx64 ":%#" PRIx64 "\n", (uint64_t) tb->pc, (uint64_t) tb->cs_base,
                   (uint64_t) env->eip);

        log_host_disas(tb->tc.ptr, gen_code_size);
        libcpu_log("\n");
    }

    int search_size = encode_search(s, tb, (void *) gen_code_buf + gen_code_size);
    if (unlikely(search_size < 0)) {
        abort();
    }

    qatomic_set(&tcg_ctx->code_gen_ptr,
                (void *) ROUND_UP((uintptr_t) gen_code_buf + gen_code_size + search_size, CODE_GEN_ALIGN));

    tb->tc.size = gen_code_size;

#if defined(CONFIG_SYMBEX_MP)
    if (env_cpu(env)->generate_llvm) {
        assert(tb->llvm_function == NULL);
        tb->llvm_function = tcg_llvm_gen_code(tcg_llvm_translator, s, tb);
        g_sqi.tb.set_tb_function(tb->se_tb, tb->llvm_function);
    }
#endif

    /* init jump list */
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_list_head = (uintptr_t) NULL;
    tb->jmp_list_next[0] = (uintptr_t) NULL;
    tb->jmp_list_next[1] = (uintptr_t) NULL;
    tb->jmp_dest[0] = (uintptr_t) NULL;
    tb->jmp_dest[1] = (uintptr_t) NULL;

    /* init original jump addresses which have been set during tcg_gen_code() */
    if (tb->jmp_reset_offset[0] != TB_JMP_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

#ifdef CONFIG_SYMBEX
    tb->instrumented = g_sqi.tb.is_tb_instrumented(tb->se_tb);
#endif

    return 0;
}
