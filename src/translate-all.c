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

#include <cpu/config.h>

#define NO_CPU_IO_DEFS
#include <tcg/tcg.h>
#include "cpu.h"
#include "timer.h"

#ifdef CONFIG_SYMBEX
#include <tcg/tcg-llvm.h>
#endif

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

/* code generation context */
TCGContext tcg_ctx;

#if defined(CONFIG_SYMBEX) && defined(TCG_KEEP_OPC)

unsigned g_gen_opc_buf_count;
unsigned g_gen_opparam_buf_count;

uint16_t *g_gen_opc_buf;
TCGArg *g_gen_opparam_buf;

uint16_t *g_gen_opc_buf_max;
TCGArg *g_gen_opparam_buf_max;

/* Preserve variable assignments to generate LLVM code when needed */
unsigned g_gen_temps_count;
TCGTemp *g_gen_temps_buf;
TCGTemp *g_gen_temps_buf_max;
TCGTemp *gen_temps_buf;

uint16_t *gen_opc_buf;
TCGArg *gen_opparam_buf;

#else
uint16_t gen_opc_buf[OPC_BUF_SIZE];
TCGArg gen_opparam_buf[OPPARAM_BUF_SIZE];
#endif

target_ulong gen_opc_pc[OPC_BUF_SIZE];
uint16_t gen_opc_icount[OPC_BUF_SIZE];
uint8_t gen_opc_instr_start[OPC_BUF_SIZE];
uint8_t gen_opc_instr_size[OPC_BUF_SIZE];

#ifdef CONFIG_SYMBEX
int cpu_gen_flush_needed(void) {
#ifdef TCG_KEEP_OPC
    return ((g_gen_opc_buf_max - gen_opc_buf < OPC_BUF_SIZE) ||
            (g_gen_opparam_buf_max - gen_opparam_buf < OPPARAM_BUF_SIZE) ||
            (g_gen_temps_buf_max - gen_temps_buf) < TCG_MAX_TEMPS);
#else
    return 0;
#endif
}

void cpu_gen_flush(void) {
#ifdef TCG_KEEP_OPC
    gen_opc_buf = g_gen_opc_buf;
    gen_opparam_buf = g_gen_opparam_buf;
    gen_temps_buf = g_gen_temps_buf;
#endif
}

void cpu_gen_init_opc(void) {
#ifdef TCG_KEEP_OPC
    // XXX: these constants have to be fine-tuned.
    extern int code_gen_max_blocks;
    g_gen_opc_buf_count = 32 * code_gen_max_blocks;
    g_gen_opc_buf = g_malloc0(g_gen_opc_buf_count * sizeof(uint16_t));
    g_gen_opc_buf_max = g_gen_opc_buf + g_gen_opc_buf_count;

    g_gen_opparam_buf_count = 4 * 32 * code_gen_max_blocks;
    g_gen_opparam_buf = g_malloc0(g_gen_opc_buf_count * sizeof(TCGArg));
    g_gen_opparam_buf_max = g_gen_opparam_buf + g_gen_opparam_buf_count;

    g_gen_temps_count = 8 * code_gen_max_blocks;
    g_gen_temps_buf = g_malloc0(g_gen_temps_count * sizeof(TCGTemp));
    g_gen_temps_buf_max = g_gen_temps_buf + g_gen_temps_count;

    gen_opc_buf = g_gen_opc_buf;
    gen_opparam_buf = g_gen_opparam_buf;
    gen_temps_buf = g_gen_temps_buf;
#endif
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
    __ldb_mmu, __ldw_mmu, __ldl_mmu, __ldq_mmu,
};

/* legacy helper signature: __st_mmu(target_ulong addr, uintxx_t val,
   int mmu_idx) */
static void *qemu_st_helpers[4] = {
    __stb_mmu, __stw_mmu, __stl_mmu, __stq_mmu,
};
#endif

void cpu_gen_init(void) {
    memcpy(tcg_ctx.qemu_ld_helpers, qemu_ld_helpers, sizeof(tcg_ctx.qemu_ld_helpers));
    memcpy(tcg_ctx.qemu_st_helpers, qemu_st_helpers, sizeof(tcg_ctx.qemu_st_helpers));

#if defined(CONFIG_SYMBEX) && defined(TCG_ENABLE_MEM_TRACING)
    tcg_ctx.qemu_ld_trace_helpers[0] = g_sqi.mem.__ldb_mmu_trace;
    tcg_ctx.qemu_ld_trace_helpers[1] = g_sqi.mem.__ldw_mmu_trace;
    tcg_ctx.qemu_ld_trace_helpers[2] = g_sqi.mem.__ldl_mmu_trace;
    tcg_ctx.qemu_ld_trace_helpers[3] = g_sqi.mem.__ldq_mmu_trace;

    tcg_ctx.qemu_st_trace_helpers[0] = g_sqi.mem.__stb_mmu_trace;
    tcg_ctx.qemu_st_trace_helpers[1] = g_sqi.mem.__stw_mmu_trace;
    tcg_ctx.qemu_st_trace_helpers[2] = g_sqi.mem.__stl_mmu_trace;
    tcg_ctx.qemu_st_trace_helpers[3] = g_sqi.mem.__stq_mmu_trace;
#endif

    extern CPUArchState *env;
    tcg_ctx.tcg_struct_size = sizeof(tcg_ctx);
    tcg_ctx.env_ptr = (uintptr_t) &env;
    tcg_ctx.env_offset_eip = offsetof(CPUArchState, eip);
    tcg_ctx.env_sizeof_eip = sizeof(env->eip);
    tcg_ctx.env_offset_ccop = offsetof(CPUArchState, cc_op);
    tcg_ctx.env_sizeof_ccop = sizeof(env->cc_op);
    tcg_ctx.env_offset_df = offsetof(CPUArchState, df);
    tcg_ctx.env_offset_tlb[0] = offsetof(CPUArchState, tlb_table[0][0]);
    tcg_ctx.env_offset_tlb[1] = offsetof(CPUArchState, tlb_table[1][0]);
    tcg_ctx.env_offset_tlb[2] = offsetof(CPUArchState, tlb_table[2][0]);

    tcg_ctx.tlbe_size = sizeof(CPUTLBEntry);
    tcg_ctx.tlbe_offset_addend = offsetof(CPUTLBEntry, addend);
    tcg_ctx.tlbe_offset_addr_read = offsetof(CPUTLBEntry, addr_read);
    tcg_ctx.tlbe_offset_addr_write = offsetof(CPUTLBEntry, addr_write);

#ifdef CONFIG_SYMBEX
    tcg_ctx.tlbe_offset_symbex_addend = offsetof(CPUTLBEntry, se_addend);
    tcg_ctx.after_memory_access_signals_count = (uintptr_t) g_sqi.events.after_memory_access_signals_count;
#endif

    tcg_ctx.target_page_bits = TARGET_PAGE_BITS;
    tcg_ctx.cpu_tlb_entry_bits = CPU_TLB_ENTRY_BITS;
    tcg_ctx.cpu_tlb_size = CPU_TLB_SIZE;

    tcg_context_init(&tcg_ctx);
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

    tcg_ctx.after_memory_access_signals_count = (uintptr_t) g_sqi.events.after_memory_access_signals_count;
}

#endif

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb, int *gen_code_size_ptr) {
    TCGContext *s = &tcg_ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count1++; /* includes aborted translations because of
                       exceptions */
    ti = profile_getclock();
#endif
    tcg_func_start(s);

#if defined(CONFIG_SYMBEX) && defined(TCG_KEEP_OPC)
    tb->gen_opc_buf = gen_opc_buf;
    tb->gen_opparam_buf = gen_opparam_buf;
#endif

    gen_intermediate_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count++;
    s->interm_time += profile_getclock() - ti;
    s->code_time -= profile_getclock();
#endif

#ifdef CONFIG_SYMBEX
    cpu_gen_code_init_ctx(s, tb);
#endif

    gen_code_size = tcg_gen_code(s, gen_code_buf);
    *gen_code_size_ptr = gen_code_size;

#ifdef CONFIG_SYMBEX
    tb->tc_size = gen_code_size;
    tcg_calc_regmask(s, &tb->reg_rmask, &tb->reg_wmask, &tb->helper_accesses_mem);

    tb->instrumented = g_sqi.tb.is_tb_instrumented(tb);
    g_sqi.tb.increment_tb_stats(tb);

#ifdef TCG_KEEP_OPC
    gen_opc_buf = gen_opc_ptr;
    gen_opparam_buf = gen_opparam_ptr;
    tb->gen_opc_count = (unsigned) (gen_opc_buf - tb->gen_opc_buf);

    /* Save variables */
    tb->tcg_temps = gen_temps_buf;
    tb->tcg_nb_globals = tcg_ctx.nb_globals;
    tb->tcg_nb_temps = tcg_ctx.nb_temps;
    unsigned vars = tb->tcg_nb_globals + tb->tcg_nb_temps;
    memcpy(tb->tcg_temps, tcg_ctx.temps, vars * sizeof(TCGTemp));
    gen_temps_buf += vars;
#endif
#endif

#ifdef CONFIG_PROFILER
    s->code_time += profile_getclock();
    s->code_in_len += tb->size;
    s->code_out_len += gen_code_size;
#endif

    return 0;
}

#ifdef CONFIG_SYMBEX

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
void restore_state_to_opc_compare(CPUX86State *env, TranslationBlock *tb, int pc_pos);
/* The cpu state corresponding to 'searched_pc' is restored.
 */
static int cpu_restore_state_original(TranslationBlock *tb, CPUArchState *env, uintptr_t searched_pc) {
    TCGContext *s = &tcg_ctx;
    int j;
    uintptr_t tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    gen_intermediate_code_pc(env, tb);

    /* find opc index corresponding to search_pc */
    tc_ptr = (uintptr_t) tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (uint8_t *) tc_ptr, searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (gen_opc_instr_start[j] == 0)
        j--;

    env->icount_decr.u16.low -= gen_opc_icount[j];

    restore_state_to_opc_compare(env, tb, j);

    return 0;
}
#endif

int cpu_restore_state_retranslate(TranslationBlock *tb, CPUArchState *env, uintptr_t searched_pc);

int cpu_restore_state(TranslationBlock *tb, CPUArchState *env, uintptr_t searched_pc) {
#if 0
    libcpu_log("RESTORE: searched_pc=%#"PRIx64" tc_ptr=%#"PRIx64" tc_ptr_max=%#"PRIx64" icount=%d cur_pc=%#x\n",
             searched_pc, (uintptr_t)tb->tc_ptr, (uintptr_t)tb->tc_ptr + tb->tc_size, tb->icount, env->eip);
#endif
    if (!g_sqi.exec.is_running_concrete()) {
#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING
        assert(env->eip == env->precise_eip);
#endif
#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
        cpu_restore_state_original(tb, env, searched_pc);
#endif
        // XXX: Need to set the instruction size here
        env->restored_instruction_size = 0;
        assert(tb->llvm_function);
        return 0;
    }

#ifdef SE_ENABLE_RETRANSLATION
    if (!tb->instrumented) {
        assert(tb->precise_entries == -1);
        // Restore PC using retranslation
        return cpu_restore_state_retranslate(tb, env, searched_pc);
    }
#endif

    tb_precise_pc_t *p = tb->precise_pcs + tb->precise_entries - 1;
    assert(tb->precise_entries > 0);
    target_ulong next_pc = tb->pc + p->guest_pc_increment;
    while (p >= tb->precise_pcs) {
#if 0
        libcpu_log("   current_host_pc=%#"PRIx64" current_guest_pc=%#x cc_op=%d tc_idx=%d\n",
                 p->host_pc, p->guest_pc, p->cc_op, p->opc);
#endif
        // assert(p->host_pc);

        if (((uintptr_t) tb->tc_ptr + p->host_pc_increment) <= searched_pc) {
            /* Found the guest program counter at the time of exception */
            se_restore_state_to_opc(env, tb, tb->pc + p->guest_pc_increment, p->cc_op, next_pc);
            env->restored_instruction_size = p->guest_inst_size;

#ifdef ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
            cpu_restore_state_original(tb, env, searched_pc);
#endif
            return 0;
        }
        next_pc = tb->pc + p->guest_pc_increment;
        --p;
    }

    assert(false && "Could not find pc");
}

#endif

#ifdef CONFIG_SYMBEX
int cpu_restore_state_retranslate(TranslationBlock *tb, CPUArchState *env, uintptr_t searched_pc)
#else

/* The cpu state corresponding to 'searched_pc' is restored.
 */
int cpu_restore_state(TranslationBlock *tb, CPUArchState *env, uintptr_t searched_pc)
#endif
{
    TCGContext *s = &tcg_ctx;
    int j;
    uintptr_t tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    /* The following does not actually retranslate code when in symbolic execution mode,
     * but looks at the precise_pc array to find the right instruction. */
    gen_intermediate_code_pc(env, tb);

    /* find opc index corresponding to search_pc */
    tc_ptr = (uintptr_t) tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

#ifdef CONFIG_SYMBEX
    cpu_gen_code_init_ctx(s, tb);
#endif

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (uint8_t *) tc_ptr, searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (gen_opc_instr_start[j] == 0)
        j--;

    restore_state_to_opc(env, tb, j);

#ifdef CONFIG_PROFILER
    s->restore_time += profile_getclock() - ti;
    s->restore_count++;
#endif

    return 0;
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

#ifdef TCG_KEEP_OPC
    /* Restore variables */
    unsigned vars = tb->tcg_nb_globals + tb->tcg_nb_temps;
    memcpy(tcg_ctx.temps, tb->tcg_temps, vars * sizeof(TCGTemp));

    uint16_t *gen_opc_buf_prev = gen_opc_buf;
    TCGArg *gen_opparam_buf_pref = gen_opparam_buf;

    gen_opc_buf = tb->gen_opc_buf;
    gen_opparam_buf = tb->gen_opparam_buf;
#endif

    tb->llvm_function = tcg_llvm_gen_code(tcg_llvm_ctx, s);
    g_sqi.tb.set_tb_function(tb);

#ifdef TCG_KEEP_OPC
    gen_opc_buf = gen_opc_buf_prev;
    gen_opparam_buf = gen_opparam_buf_pref;
#endif
    return 0;
}

#endif
