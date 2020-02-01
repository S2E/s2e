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
#include <tcg/tcg.h>
#include "cpu.h"
#include "qemu-lock.h"
#include "timer.h"

#if defined(CONFIG_SYMBEX_MP) || defined(STATIC_TRANSLATOR)
#include <tcg/tcg-llvm.h>
#endif

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include "exec-tb.h"
#include "exec.h"

/* code generation context */
__thread TCGContext *tcg_ctx;

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE (128 * 1024 * 1024)

/* Maximum size of the code gen buffer we'd like to use.  Unless otherwise
   indicated, this is constrained by the range of direct branches on the
   host cpu, as used by the TCG implementation of goto_tb.  */
#if defined(__x86_64__)
#define MAX_CODE_GEN_BUFFER_SIZE (2ul * 1024 * 1024 * 1024)
#else
#define MAX_CODE_GEN_BUFFER_SIZE ((size_t) -1)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (32u * 1024 * 1024)

#define DEFAULT_CODE_GEN_BUFFER_SIZE                                                            \
    (DEFAULT_CODE_GEN_BUFFER_SIZE_1 < MAX_CODE_GEN_BUFFER_SIZE ? DEFAULT_CODE_GEN_BUFFER_SIZE_1 \
                                                               : MAX_CODE_GEN_BUFFER_SIZE)

static inline size_t size_code_gen_buffer(size_t tb_size) {
    /* Size the buffer.  */
    if (tb_size == 0) {
        tb_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
    }

    if (tb_size < MIN_CODE_GEN_BUFFER_SIZE) {
        tb_size = MIN_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size > MAX_CODE_GEN_BUFFER_SIZE) {
        tb_size = MAX_CODE_GEN_BUFFER_SIZE;
    }
    return tb_size;
}

// XXX: deduplicate this
#define CODE_GEN_ALIGN 16

static inline void *alloc_code_gen_buffer(TCGContext *ctx) {
    size_t length = ctx->code_gen_buffer_size;
    void *buf = mmap(NULL, length, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *end = buf + length;
    size_t size;

    /* page-align the beginning and end of the buffer */
    buf = ALIGN_PTR_UP(buf, 0x1000);
    end = ALIGN_PTR_DOWN(end, 0x1000);

    size = end - buf;

    /* Honor a command-line option limiting the size of the buffer.  */
    if (size > ctx->code_gen_buffer_size) {
        size = ALIGN_DOWN(ctx->code_gen_buffer_size, 0x1000);
    }
    ctx->code_gen_buffer_size = size;

    if (mprotect(buf, size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        abort();
    }

    madvise(buf, size, MADV_HUGEPAGE);

    return buf;
}

static inline void code_gen_alloc(TCGContext *tcg, size_t tb_size) {
    tcg->code_gen_buffer_size = size_code_gen_buffer(tb_size);
    tcg->code_gen_buffer = alloc_code_gen_buffer(tcg);
    if (tcg->code_gen_buffer == NULL) {
        fprintf(stderr, "Could not allocate dynamic translator buffer\n");
        exit(1);
    }
}

#if defined(CONFIG_SYMBEX_MP) || defined(STATIC_TRANSLATOR)
static void *qemu_ld_helpers[4] = {
    helper_ldb_mmu_symb,
    helper_ldw_mmu_symb,
    helper_ldl_mmu_symb,
    helper_ldq_mmu_symb,
};

static void *qemu_st_helpers[4] = {
    helper_stb_mmu_symb,
    helper_stw_mmu_symb,
    helper_stl_mmu_symb,
    helper_stq_mmu_symb,
};
#else
static void *qemu_ld_helpers[4] = {
    helper_ldb_mmu,
    helper_ldw_mmu,
    helper_ldl_mmu,
    helper_ldq_mmu,
};

/* legacy helper signature: __st_mmu(target_ulong addr, uintxx_t val,
   int mmu_idx) */
static void *qemu_st_helpers[4] = {
    helper_stb_mmu,
    helper_stw_mmu,
    helper_stl_mmu,
    helper_stq_mmu,
};
#endif

static void cpu_gen_init(TCGContext *ctx, tcg_settings_t *settings) {

    settings->tlb_flags_mask = TLB_FLAGS_MASK;
    settings->tlb_mask_offset = offsetof(CPUX86State, tlb_mask);
    settings->tlb_entry_addend_offset = offsetof(CPUTLBEntry, addend);
    settings->tlb_entry_addr_read_offset = offsetof(CPUTLBEntry, addr_read);
    settings->tlb_entry_addr_write_offset = offsetof(CPUTLBEntry, addr_write);

    code_gen_alloc(ctx, 0);

    memcpy(ctx->qemu_ld_helpers, qemu_ld_helpers, sizeof(tcg_ctx->qemu_ld_helpers));
    memcpy(ctx->qemu_st_helpers, qemu_st_helpers, sizeof(tcg_ctx->qemu_st_helpers));

#if defined(CONFIG_SYMBEX) && defined(TCG_ENABLE_MEM_TRACING)
    ctx->qemu_ld_trace_helpers[0] = g_sqi.mem.__ldb_mmu_trace;
    ctx->qemu_ld_trace_helpers[1] = g_sqi.mem.__ldw_mmu_trace;
    ctx->qemu_ld_trace_helpers[2] = g_sqi.mem.__ldl_mmu_trace;
    ctx->qemu_ld_trace_helpers[3] = g_sqi.mem.__ldq_mmu_trace;

    ctx->qemu_st_trace_helpers[0] = g_sqi.mem.__stb_mmu_trace;
    ctx->qemu_st_trace_helpers[1] = g_sqi.mem.__stw_mmu_trace;
    ctx->qemu_st_trace_helpers[2] = g_sqi.mem.__stl_mmu_trace;
    ctx->qemu_st_trace_helpers[3] = g_sqi.mem.__stq_mmu_trace;
#endif

    extern CPUArchState *env;
    ctx->tcg_struct_size = sizeof(*tcg_ctx);
    ctx->env_ptr = (uintptr_t) &env;
    ctx->env_offset_eip = offsetof(CPUArchState, eip);
    ctx->env_sizeof_eip = sizeof(env->eip);
    ctx->env_offset_ccop = offsetof(CPUArchState, cc_op);
    ctx->env_sizeof_ccop = sizeof(env->cc_op);
    ctx->env_offset_df = offsetof(CPUArchState, df);

    ctx->env_offset_tlb[0] = offsetof(CPUArchState, tlb_table[0]);
    ctx->env_offset_tlb[1] = offsetof(CPUArchState, tlb_table[1]);
    ctx->env_offset_tlb[2] = offsetof(CPUArchState, tlb_table[2]);

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

    tcg_context_init(ctx);
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(unsigned long tb_size) {
    cpu_gen_init(&tcg_init_ctx, &g_tcg_settings);
    code_gen_alloc(&tcg_init_ctx, tb_size);

    // tcg_register_jit(code_gen_buffer, code_gen_buffer_size);

    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);

    tcg_region_init();
}

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb) {
    TCGContext *s = tcg_ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;

    tb->tc.ptr = tcg_ctx->code_gen_ptr;

    tcg_func_start(s);

    gen_intermediate_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc.ptr;

    tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
    tcg_ctx->tb_jmp_reset_offset = tb->jmp_reset_offset;
    if (TCG_TARGET_HAS_direct_jump) {
        tcg_ctx->tb_jmp_insn_offset = tb->jmp_target_arg;
        tcg_ctx->tb_jmp_target_addr = NULL;
    } else {
        tcg_ctx->tb_jmp_insn_offset = NULL;
        tcg_ctx->tb_jmp_target_addr = tb->jmp_target_arg;
    }

    gen_code_size = tcg_gen_code(s, tb);
    if (unlikely(gen_code_size < 0)) {
        return -1;
    }

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

    atomic_set(&tcg_ctx->code_gen_ptr,
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
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

#ifdef CONFIG_SYMBEX
    tb->instrumented = g_sqi.tb.is_tb_instrumented(tb->se_tb);
    g_sqi.tb.increment_tb_stats(tb);
#endif

    return 0;
}
