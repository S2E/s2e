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
#include <tcg/utils/cache.h>
#include <tcg/utils/spinlock.h>
#include "cpu.h"
#include "timer.h"

#if defined(CONFIG_SYMBEX_MP) || defined(STATIC_TRANSLATOR)
#include <tcg/tcg-llvm.h>
#endif

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include "exec-tb.h"
#include "exec.h"

extern TCGContext tcg_init_ctx;

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE (128 * 1024 * 1024)

#if defined(CONFIG_SYMBEX_MP)
tcg_target_ulong tcg_helper_ldb_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
tcg_target_ulong tcg_helper_ldw_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
tcg_target_ulong tcg_helper_ldl_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
uint64_t tcg_helper_ldq_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);

static void *qemu_ld_helpers[(MO_SIZE | MO_BSWAP) + 1] = {[MO_UB] = tcg_helper_ldb_mmu_symb,
                                                          [MO_LEUW] = tcg_helper_ldw_mmu_symb,
                                                          [MO_LEUL] = tcg_helper_ldl_mmu_symb,
                                                          [MO_LEUQ] = tcg_helper_ldq_mmu_symb};

static void *qemu_st_helpers[(MO_SIZE | MO_BSWAP) + 1] = {[MO_UB] = helper_stb_mmu_symb,
                                                          [MO_LEUW] = helper_stw_mmu_symb,
                                                          [MO_LEUL] = helper_stl_mmu_symb,
                                                          [MO_LEUQ] = helper_stq_mmu_symb};
#elif defined(STATIC_TRANSLATOR)

static void *qemu_ld_helpers[(MO_SIZE | MO_BSWAP) + 1] = {0};
static void *qemu_st_helpers[(MO_SIZE | MO_BSWAP) + 1] = {0};

#else
tcg_target_ulong tcg_helper_ldb_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
tcg_target_ulong tcg_helper_ldw_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
tcg_target_ulong tcg_helper_ldl_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
uint64_t tcg_helper_ldq_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);

static void *qemu_ld_helpers[(MO_SIZE | MO_BSWAP) + 1] = {[MO_UB] = tcg_helper_ldb_mmu,
                                                          [MO_LEUW] = tcg_helper_ldw_mmu,
                                                          [MO_LEUL] = tcg_helper_ldl_mmu,
                                                          [MO_LEUQ] = tcg_helper_ldq_mmu};

/* legacy helper signature: __st_mmu(target_ulong addr, uintxx_t val,
   int mmu_idx) */
static void *qemu_st_helpers[(MO_SIZE | MO_BSWAP) + 1] = {
    [MO_UB] = helper_stb_mmu, [MO_LEUW] = helper_stw_mmu, [MO_LEUL] = helper_stl_mmu, [MO_LEUQ] = helper_stq_mmu};
#endif

static void cpu_gen_init(TCGContext *ctx) {
    memcpy(ctx->qemu_ld_helpers, qemu_ld_helpers, sizeof(ctx->qemu_ld_helpers));
    memcpy(ctx->qemu_st_helpers, qemu_st_helpers, sizeof(ctx->qemu_st_helpers));

    extern CPUArchState *env;
    ctx->tcg_struct_size = sizeof(*ctx);
    ctx->env_ptr = (uintptr_t) &env;
    ctx->env_offset_eip = offsetof(CPUArchState, eip);
    ctx->env_sizeof_eip = sizeof(env->eip);
    ctx->env_offset_ccop = offsetof(CPUArchState, cc_op);
    ctx->env_sizeof_ccop = sizeof(env->cc_op);
    ctx->env_offset_df = offsetof(CPUArchState, df);

    ctx->tlbe_size = sizeof(CPUTLBEntry);
    ctx->tlbe_offset_addend = offsetof(CPUTLBEntry, addend);
    ctx->tlbe_offset_addr_read = offsetof(CPUTLBEntry, addr_read);
    ctx->tlbe_offset_addr_write = offsetof(CPUTLBEntry, addr_write);

#ifdef CONFIG_SYMBEX
    ctx->tlbe_offset_symbex_addend = offsetof(CPUTLBEntry, se_addend);
#endif

    ctx->target_page_bits = TARGET_PAGE_BITS;
    ctx->cpu_tlb_entry_bits = CPU_TLB_ENTRY_BITS;
    ctx->cpu_tlb_size = CPU_TLB_SIZE;
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(unsigned long tb_size) {
    if (init_cache_info() < 0) {
        fprintf(stderr, "Could not init cache size");
        exit(-1);
    }

    tcg_init(MIN_CODE_GEN_BUFFER_SIZE, 0, 1);
    cpu_gen_init(&tcg_init_ctx);

    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);
}

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
    int max_insns = TCG_MAX_INSNS;

    //    tb->tc.ptr = tcg_ctx->code_gen_ptr;
    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;

    tcg_ctx->gen_tb = tb;
    tcg_ctx->addr_type = TARGET_LONG_BITS == 32 ? TCG_TYPE_I32 : TCG_TYPE_I64;

#ifdef CONFIG_SOFTMMU
    tcg_ctx->page_bits = TARGET_PAGE_BITS;
    tcg_ctx->page_mask = TARGET_PAGE_MASK;
    tcg_ctx->tlb_dyn_max_bits = CPU_TLB_DYN_MAX_BITS;
    tcg_ctx->tlb_fast_offset =
        offsetof(CPUX86State, tlb_table); // (int) offsetof(ArchCPU, neg.tlb.f) - (int) offsetof(ArchCPU, env);
#endif
    tcg_ctx->insn_start_words = TARGET_INSN_START_WORDS;
#ifdef TCG_GUEST_DEFAULT_MO
    tcg_ctx->guest_mo = TCG_GUEST_DEFAULT_MO;
#else
    tcg_ctx->guest_mo = TCG_MO_ALL;
#endif

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
    gen_code_buf = tb->tc.ptr;

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

#if defined(CONFIG_SYMBEX_MP) || defined(STATIC_TRANSLATOR)
    if (env->generate_llvm) {
        assert(tb->llvm_function == NULL);
        tb->llvm_function = tcg_llvm_gen_code(tcg_llvm_translator, s, tb);
        g_sqi.tb.set_tb_function(tb->se_tb, tb->llvm_function);
    }
#endif

    /* init jump list */
    tb->jmp_lock = SPIN_LOCK_UNLOCKED;
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
