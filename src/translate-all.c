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
#include <cpu/tlb.h>
#include <cpu/types.h>

#define NO_CPU_IO_DEFS
#include <tcg/tcg.h>
#include "cpu.h"
#include "qemu-lock.h"
#include "timer.h"

#ifdef CONFIG_SYMBEX
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

#ifdef CONFIG_SYMBEX
int cpu_gen_flush_needed(void) {
    return 0;
}
#endif

#ifdef CONFIG_SYMBEX
static void *qemu_ld_helpers[4] = {
    __ldb_mmu_symb, __ldw_mmu_symb, __ldl_mmu_symb, __ldq_mmu_symb,
};

static void *qemu_st_helpers[4] = {
    __stb_mmu_symb, __stw_mmu_symb, __stl_mmu_symb, __stq_mmu_symb,
};
#else
static void *qemu_ld_helpers[4] = {
    helper_ldb_mmu, helper_ldw_mmu, helper_ldl_mmu, helper_ldq_mmu,
};

/* legacy helper signature: __st_mmu(target_ulong addr, uintxx_t val,
   int mmu_idx) */
static void *qemu_st_helpers[4] = {
    helper_stb_mmu, helper_stw_mmu, helper_stl_mmu, helper_stq_mmu,
};
#endif

static void page_init(void) {
    /* NOTE: we can always suppose that qemu_host_page_size >=
       TARGET_PAGE_SIZE */

    qemu_real_host_page_size = getpagesize();

    if (qemu_host_page_size == 0)
        qemu_host_page_size = qemu_real_host_page_size;
    if (qemu_host_page_size < TARGET_PAGE_SIZE)
        qemu_host_page_size = TARGET_PAGE_SIZE;

    qemu_host_page_mask = ~(qemu_host_page_size - 1);
}

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
    ctx->after_memory_access_signals_count = (uintptr_t) g_sqi.events.after_memory_access_signals_count;
#endif

    ctx->target_page_bits = TARGET_PAGE_BITS;
    ctx->cpu_tlb_entry_bits = CPU_TLB_ENTRY_BITS;
    ctx->cpu_tlb_size = CPU_TLB_SIZE;

    tcg_context_init(ctx);
}

#ifdef CONFIG_SYMBEX
static void cpu_gen_code_init_ctx(TCGContext *s, TranslationBlock *tb) {
    s->tb_pc = tb->pc;
    s->tb_cs_base = tb->cs_base;
    s->tb_flags = tb->flags;
    s->tb_size = tb->size;
    s->tb_tc_size = tb->tc_size;
    s->tb_instrumented = tb->instrumented;
    s->precise_pcs = tb->precise_pcs;
    s->precise_entries = tb->precise_entries;

    tcg_ctx->after_memory_access_signals_count = (uintptr_t) g_sqi.events.after_memory_access_signals_count;
}

#endif

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(unsigned long tb_size) {
    cpu_gen_init(&tcg_init_ctx, &g_tcg_settings);
    code_gen_alloc(&tcg_init_ctx, tb_size);

    // tcg_register_jit(code_gen_buffer, code_gen_buffer_size);
    page_init();

    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);

    tcg_region_init();
}

/* Encode VAL as a signed leb128 sequence at P.
   Return P incremented past the encoded value.  */
static uint8_t *encode_sleb128(uint8_t *p, target_long val) {
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

/* Decode a signed leb128 sequence at *PP; increment *PP past the
   decoded value.  Return the decoded value.  */
static target_long decode_sleb128(uint8_t **pp) {
    uint8_t *p = *pp;
    target_long val = 0;
    int byte, shift = 0;

    do {
        byte = *p++;
        val |= (target_ulong)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < TARGET_LONG_BITS && (byte & 0x40)) {
        val |= -(target_ulong) 1 << shift;
    }

    *pp = p;
    return val;
}

/* Encode the data collected about the instructions while compiling TB.
   Place the data at BLOCK, and return the number of bytes consumed.

   The logical table consists of TARGET_INSN_START_WORDS target_ulong's,
   which come from the target's insn_start data, followed by a uintptr_t
   which comes from the host pc of the end of the code implementing the insn.

   Each line of the table is encoded as sleb128 deltas from the previous
   line.  The seed for the first line is { tb->pc, 0..., tb->tc.ptr }.
   That is, the first column is seeded with the guest pc, the last column
   with the host pc, and the middle columns with zeros.  */

static int encode_search(TCGContext *tcg_ctx, TranslationBlock *tb, uint8_t *block) {
    uint8_t *highwater = tcg_ctx->code_gen_highwater;
    uint8_t *p = block;
    int i, j, n;

    for (i = 0, n = tb->icount; i < n; ++i) {
        target_ulong prev;

        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (j == 0 ? tb->pc : 0);
            } else {
                prev = tcg_ctx->gen_insn_data[i - 1][j];
            }
            p = encode_sleb128(p, tcg_ctx->gen_insn_data[i][j] - prev);
        }
        prev = (i == 0 ? 0 : tcg_ctx->gen_insn_end_off[i - 1]);
        p = encode_sleb128(p, tcg_ctx->gen_insn_end_off[i] - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

    return p - block;
}

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb, int *gen_code_size_ptr) {
    TCGContext *s = tcg_ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;

    tcg_func_start(s);

#if defined(CONFIG_SYMBEX) && defined(TCG_KEEP_OPC)
    tb->gen_opc_buf = gen_opc_buf;
    tb->gen_opparam_buf = gen_opparam_buf;
#endif

    gen_intermediate_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc.ptr;

#ifdef CONFIG_SYMBEX
    cpu_gen_code_init_ctx(s, tb);
#endif

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

    *gen_code_size_ptr = gen_code_size;

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
    tb->tc_size = gen_code_size;
    tcg_calc_regmask(s, &tb->reg_rmask, &tb->reg_wmask, &tb->helper_accesses_mem);

    tb->instrumented = g_sqi.tb.is_tb_instrumented(tb);
    g_sqi.tb.increment_tb_stats(tb);
#endif

    return 0;
}

int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc) {
    target_ulong data[TARGET_INSN_START_WORDS] = {tb->pc};
    uintptr_t host_pc = (uintptr_t) tb->tc.ptr;
    uint8_t *p = tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    if (pc < tb->pc || pc >= tb->pc + tb->size) {
        return 0;
    }

    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        host_pc += decode_sleb128(&p);
        if (data[0] == pc) {
            if (i == num_insns - 1) {
                return tb->size - (pc - tb->pc);
            } else {
                for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
                    data[j] += decode_sleb128(&p);
                }
                return data[0] - pc;
            }
        }
    }

    return 0;
}

static int tb_find_guest_pc(TranslationBlock *tb, uintptr_t searched_host_pc, target_ulong *data) {
    uintptr_t host_pc = (uintptr_t) tb->tc.ptr;
    uint8_t *p = tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    searched_host_pc -= GETPC_ADJ;

    if (searched_host_pc < host_pc) {
        return -1;
    }

    // Reconstruct the stored insn data while looking for the point at
    // which the end of the insn exceeds the searched_pc.
    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        host_pc += decode_sleb128(&p);
        if (host_pc > searched_host_pc) {
            return 0;
        }
    }
    return -1;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 * When reset_icount is true, current TB will be interrupted and
 * icount should be recalculated.
 */
static int cpu_restore_state_from_tb(CPUArchState *env, TranslationBlock *tb, uintptr_t searched_pc) {
    target_ulong data[TARGET_INSN_START_WORDS] = {tb->pc};

    if (tb_find_guest_pc(tb, searched_pc, data) < 0) {
        return -1;
    }

    restore_state_to_opc(env, tb, data);

    return 0;
}

bool cpu_restore_state(CPUArchState *env, uintptr_t host_pc) {
    TranslationBlock *tb;
    bool r = false;
    uintptr_t check_offset;

    /* The host_pc has to be in the region of current code buffer. If
     * it is not we will not be able to resolve it here. The two cases
     * where host_pc will not be correct are:
     *
     *  - fault during translation (instruction fetch)
     *  - fault from helper (not using GETPC() macro)
     *
     * Either way we need return early as we can't resolve it here.
     *
     * We are using unsigned arithmetic so if host_pc <
     * tcg_init_ctx.code_gen_buffer check_offset will wrap to way
     * above the code_gen_buffer_size
     */
    check_offset = host_pc - (uintptr_t) tcg_init_ctx.code_gen_buffer;

    if (check_offset < tcg_init_ctx.code_gen_buffer_size) {
        tb = tcg_tb_lookup(host_pc);
        if (tb) {
            cpu_restore_state_from_tb(env, tb, host_pc);
            if (tb_cflags(tb) & CF_NOCACHE) {
                /* one-shot translation, invalidate it immediately */
                tb_phys_invalidate(tb, -1);
                tcg_tb_remove(tb);
            }
            r = true;
        }
    }

    return r;
}

#ifdef CONFIG_SYMBEX

/**
 * Generates LLVM code for already translated TB.
 * We need to retranslate to micro-ops and to machine code because:
 *   - QEMU throws away micro-ops and storing them is too expensive (TCG_KEEP_OPC)
 *   - x86 and LLVM code must be semantically equivalent (same instrumentation in both, etc.)
 */
int cpu_gen_llvm(CPUArchState *env, TranslationBlock *tb) {
    TCGContext *s = &tcg_ctx;
    assert(tb->llvm_function == NULL);

    /* Need to retranslate the code here because QEMU throws
       away intermediate representation once machine code is generated. */

    cpu_gen_code_init_ctx(s, tb);

    tb->llvm_function = tcg_llvm_gen_code(tcg_llvm_ctx, s);
    g_sqi.tb.set_tb_function(tb);

    return 0;
}

#endif
