/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2012  SUSE LINUX Products GmbH
/// Copyright (C) 2026  Vitaly Chipounov
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

#ifndef S2E_CPU_STATE_H
#define S2E_CPU_STATE_H

/*
 * Hand-written replacement for upstream's include/hw/core/cpu.h (PORTING.md,
 * decision 3.1). It carries upstream's layout contract: neg is the last
 * member of CPUState, and CPUArchState immediately follows CPUState inside
 * ArchCPU, so that cpu_env() / env_cpu() are pointer arithmetic and generated
 * code reaches the TLB at a fixed negative offset from env.
 *
 * CPUState holds the execution fields that upstream keeps there
 * (exception_index, interrupt_request, halted, jmp_env, the breakpoint and
 * watchpoint lists, ...), the S2E additions that go with them (the current
 * TB, the abort flag, generate_llvm), and the CPU caches: the TLB, the RAM
 * TLB and the TB jump cache. QEMU 1.0 kept all of these inside CPUX86State
 * (CPU_COMMON).
 *
 * libs2ecore registers the structure as two KLEE objects, split at neg:
 *
 *  - [0, offsetof(CPUState, neg)) holds the execution fields. They are
 *    per-state, so libs2ecore snapshots them on every state switch together
 *    with the concrete registers. jmp_env is the exception: it belongs to the
 *    host call stack performing the switch, and doStateSwitch() carries it
 *    across the restore.
 *  - [offsetof(CPUState, neg), sizeof(CPUState)) holds the caches. Only the
 *    active state has a TLB; the region is never snapshotted and is flushed
 *    on every switch (tlb-update.md).
 *
 * Both objects are shared-concrete so that helpers and the softmmu fast path
 * can reach the fields as bitcode inside KLEE. Generated code addresses the
 * execution fields through tcg_env at a negative offset, computed as
 * offsetof(ArchCPU, parent_obj.field) - offsetof(ArchCPU, env).
 *
 * The TLB keeps the QEMU 1.0 organization (fixed size, iotlb, no victim TLB,
 * no CPUTLBEntryFull); upstream's algorithms arrive with the cputlb.c import
 * (PORTING.md phase 2).
 *
 * This header is included at the end of cpu/i386/cpu.h: ArchCPU embeds
 * CPUArchState by value, so the complete CPUX86State must be visible first.
 */

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

#include <utils/compiler.h>

#include <cpu/common.h>
#include <cpu/i386/defs.h>
#include <cpu/tb.h>
#include <cpu/tlb.h>
#include <cpu/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CPUArchState
#define CPUArchState struct CPUX86State
#endif

struct TCGCPUOps;
struct TranslationBlock;

/* Data elements that are per MMU mode, minus the bits accessed by the TCG fast path. */
typedef struct CPUTLBDesc {
    target_phys_addr_t iotlb[CPU_TLB_SIZE];
    /* Backing store for the fast-path table; f[i].table points here. */
    CPUTLBEntry table[CPU_TLB_SIZE];
} CPUTLBDesc;

/* The entire softmmu tlb, for all MMU modes. */
typedef struct CPUTLB {
    CPUTLBDesc d[NB_MMU_MODES];
    CPUTLBDescFast f[NB_MMU_MODES];
    /* Region covered by large pages, one pair for all MMU modes; invalidating
       it forces a full flush (upstream 11.1 tracks this per CPUTLBDesc). */
    target_ulong tlb_flush_addr;
    target_ulong tlb_flush_mask;
} CPUTLB;

/*
 * Elements of CPUState accessed from CPUArchState via negative offsets.
 * The most frequently used members should be last, closest to env.
 */
typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;

#if defined(SE_ENABLE_PHYSRAM_TLB)
    /* The RAM TLB has no CPUTLBDescFast and keeps its own pinned size (PORTING.md 9.2). */
    CPUTLBRAMEntry se_ram_tlb[CPU_TLB_SIZE];
#endif
    /* Cached by the softmmu IO path; points into the tables above, so it
       lives and dies with them (PORTING.md 9.6). */
    CPUTLBEntry *se_tlb_current;

    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];
} CPUNegativeOffsetState;

/*
 * Common state of one CPU core or thread. Slim version of upstream's
 * CPUState: no QOM, no threading, no work queues, one address space.
 *
 * Everything before neg is snapshotted per execution state by libs2ecore.
 * cpu_common_reset() clears the fields a CPU reset discards; the others
 * (the breakpoint and watchpoint lists, single-step mode, jmp_env,
 * exception_index, generate_llvm) survive a reset.
 */
typedef struct CPUState {
    /* Replaces upstream's cpu->cc->tcg_ops; wired up when the 11.1 accel/tcg
       code lands (PORTING.md 3.1). */
    const struct TCGCPUOps *tcg_ops;

    int cpu_index;

    /* Longjmp target of the CPU loop. See the note on state switches above. */
    jmp_buf jmp_env;

    /* Nonzero if the CPU is in suspend state. */
    uint32_t halted;
    uint32_t interrupt_request;
    /* Set by cpu_exit() to leave the CPU loop; tested by generated code. */
    volatile sig_atomic_t exit_request;
    int exception_index;
    int singlestep_enabled;

    /* Currently executing TB; NULL while no generated code runs. */
    struct TranslationBlock *current_tb;
    /* TB being executed, stored by the TB itself so that a regenerated LLVM
       function still names the original TB (S2E). */
    struct TranslationBlock *se_current_tb;

    /* Softmmu support: the host pc and the guest virtual address of the
       memory access being handled, so that the MMIO helpers can restore the
       CPU state without more arguments. */
    uintptr_t mem_io_pc;
    target_ulong mem_io_vaddr;

    /* Forces the translator to put a single instruction in the next TB.
       Reset before code execution (S2E). */
    uint32_t translate_single_instruction;
    /* Set when the LLVM interpreter must exit the current TB, e.g., after
       self-modifying code invalidated it (S2E). */
    uint32_t se_tb_abort;
    /* Generate LLVM code during translation (S2E). */
    int generate_llvm;

    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;
    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    /* MUST BE LAST, to minimize the displacement to CPUArchState. */
    char neg_align[-sizeof(CPUNegativeOffsetState) % 16] QEMU_ALIGNED(16);
    CPUNegativeOffsetState neg;
} CPUState;

/* Validate placement of CPUNegativeOffsetState. */
QEMU_BUILD_BUG_ON(offsetof(CPUState, neg) != sizeof(CPUState) - sizeof(CPUNegativeOffsetState));

typedef struct ArchCPU {
    CPUState parent_obj;

    /* Must immediately follow parent_obj: cpu_env() and env_cpu() depend on it. */
    CPUArchState env;

    /* Target fields (phys_bits, cache info, ...) land here in phase 3 (PORTING.md 3.5). */
} ArchCPU;

QEMU_BUILD_BUG_ON(offsetof(ArchCPU, parent_obj) != 0);
QEMU_BUILD_BUG_ON(offsetof(ArchCPU, env) != sizeof(CPUState));

static inline CPUArchState *cpu_env(CPUState *cpu) {
    return (CPUArchState *) (cpu + 1);
}

static inline const CPUState *env_cpu_const(const CPUArchState *env) {
    return (const CPUState *) ((const char *) env - sizeof(CPUState));
}

static inline CPUState *env_cpu(CPUArchState *env) {
    return (CPUState *) env_cpu_const(env);
}

static inline ArchCPU *env_archcpu(CPUArchState *env) {
    return (ArchCPU *) env_cpu(env);
}

static inline CPUTLB *env_tlb(CPUArchState *env) {
    return &env_cpu(env)->neg.tlb;
}

/* f[] is indexed directly, without upstream's mmuidx_to_fast_index()
   inversion; libtcg's tlb_mask_table_ofs() does the same (tlb-update.md). */
static inline CPUTLBDescFast *cpu_tlb_fast(CPUState *cpu, int mmu_idx) {
    return &cpu->neg.tlb.f[mmu_idx];
}

/* Clears the execution fields that a CPU reset discards; defined in exec.c. */
void cpu_common_reset(CPUState *cpu);

#ifdef __cplusplus
}
#endif

#endif
