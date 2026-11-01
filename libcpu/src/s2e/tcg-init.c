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
/// One-time initialization of TCG and of the CPU's execution state.
///
/// tcg_exec_init() creates the TCG context and sets the fields that libtcg's
/// backend and LLVM translator read. They depend only on the target, and
/// tcg_func_start() does not reset them, so they are set once instead of for
/// every TB. tcg_exec_cpu_init() replaces upstream's tcg_exec_realizefn(), which
/// libcpu cannot call because cpu_exec_init() already calls tlb_init().

#include <cpu/config.h>
#include <cpu/types.h>
#include <tcg/tcg.h>
#include "cpu.h"
#include "exec-all.h"

#include "s2e/accel-deps.h"

#include "accel/tb-jmp-cache.h"
#include "accel/tlb-bounds.h"

#include <cpu/accel/cpu-ops.h>

extern TCGContext tcg_init_ctx;

/* S2E: upstream defines these with its command line options, which libcpu does
   not have. */
bool one_insn_per_tb;
bool icount_align_option;

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE (128 * 1024 * 1024)

static void cpu_gen_init(TCGContext *ctx) {
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
    ctx->env_offset_se_tb_abort = (int) offsetof(ArchCPU, parent_obj.se_tb_abort) - (int) offsetof(ArchCPU, env);
#endif

    ctx->target_page_bits = TARGET_PAGE_BITS;
    ctx->cpu_tlb_entry_bits = CPU_TLB_ENTRY_BITS;
    ctx->cpu_tlb_size = CPU_TLB_SIZE;

    ctx->addr_type = TARGET_LONG_BITS == 32 ? TCG_TYPE_I32 : TCG_TYPE_I64;
    ctx->page_bits = TARGET_PAGE_BITS;
    ctx->page_mask = TARGET_PAGE_MASK;
    ctx->tlb_dyn_max_bits = CPU_TLB_DYN_MAX_BITS;
    ctx->tlb_fast_offset = (int) offsetof(ArchCPU, parent_obj.neg.tlb.f) - (int) offsetof(ArchCPU, env);
}

/* Must be called before using the QEMU cpus. The size of the translation
   buffer is MIN_CODE_GEN_BUFFER_SIZE, whatever the value of 'tb_size'. */
void tcg_exec_init(unsigned long tb_size) {
    /* What upstream's tcg_init_machine() does before tcg_init(). */
    tcg_allowed = true;
    page_init();
    tb_htable_init();

    tcg_init(MIN_CODE_GEN_BUFFER_SIZE, 0, 1);
    cpu_gen_init(&tcg_init_ctx);

    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);
}

void tcg_exec_cpu_init(CPUState *cpu) {
    static bool tcg_target_initialized;

    if (!tcg_target_initialized) {
        /* Check mandatory TCGCPUOps handlers */
        const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

        assert(tcg_ops->cpu_exec_halt);
        assert(tcg_ops->cpu_exec_interrupt);
        assert(tcg_ops->cpu_exec_reset);
        assert(tcg_ops->pointer_wrap);
        assert(tcg_ops->translate_code);
        assert(tcg_ops->get_tb_cpu_state);
        assert(tcg_ops->mmu_index);
        tcg_ops->initialize();
        tcg_target_initialized = true;
    }

    cpu->tb_jmp_cache = g_new0(CPUJumpCache, 1);

    /* cpu_x86_init() allocates the CPU with zeros, and cpu_common_reset() only
       runs on an INIT interrupt. */
    cpu->cflags_next_tb = -1;

#ifdef CONFIG_SYMBEX
    /* lookup_and_goto_ptr would enter the next TB without going through the
       decisions that S2E makes for each TB in the CPU loop. */
    cpu->tcg_cflags = CF_NO_GOTO_PTR;
#endif
}
