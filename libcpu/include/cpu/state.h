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
 * The TLB structures are upstream's (accel/tcg/cputlb.c), with two
 * differences. The tables of each MMU mode are static arrays inside neg
 * instead of heap allocations, so that the KLEE object registered over neg
 * covers them and the softmmu can read them as bitcode. Their size is
 * therefore pinned (src/accel/tlb-bounds.h). MemoryRegionSection is a small
 * libcpu structure over MemoryDesc (cpu/memory.h), not upstream's.
 *
 * This header is included at the end of cpu/i386/cpu.h: ArchCPU embeds
 * CPUArchState by value, so the complete CPUX86State must be visible first.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <utils/compiler.h>

#include <cpu/common.h>
#include <cpu/exec/memattrs.h>
#include <cpu/exec/mmu-access-type.h>
#include <cpu/exec/vaddr.h>
#include <cpu/i386/defs.h>
#include <cpu/memory.h>
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

/* The part of upstream's CPUClass that accel/tcg reads. */
typedef struct CPUClass {
    const struct TCGCPUOps *tcg_ops;
} CPUClass;

typedef uint32_t MMUIdxMap;

/* Size of the victim TLB. The victim TLB is disabled (src/accel/cputlb.c),
   the arrays only exist so that the upstream code compiles unchanged. */
#define CPU_VTLB_SIZE 8

/*
 * The full TLB entry, which is not accessed by generated TCG code,
 * so the layout is not as critical as that of CPUTLBEntry. This is
 * also why we don't want to combine the two structs.
 */
typedef struct CPUTLBEntryFull {
    /*
     * @xlat_offset: TARGET_PAGE_BITS aligned offset which must be added to
     * the virtual address to obtain:
     *   + the ram_addr_t of the target RAM (if the section is RAM)
     *   + the guest physical address of the MMIO access (otherwise)
     */
    hwaddr xlat_offset;

    /* @section contains physical section. */
    MemoryRegionSection *section;

    /* @phys_addr contains the physical address of the page. */
    hwaddr phys_addr;

    /* @attrs contains the memory transaction attributes for the page. */
    MemTxAttrs attrs;

    /* @prot contains the complete protections for the page. */
    uint8_t prot;

    /* @lg_page_size contains the log2 of the page size. */
    uint8_t lg_page_size;

    /* Additional tlb flags requested by tlb_fill. */
    uint8_t tlb_fill_flags;

    /*
     * Additional tlb flags for use by the slow path. If non-zero,
     * the corresponding CPUTLBEntry comparator must have TLB_FORCE_SLOW.
     */
    uint8_t slow_flags[MMU_ACCESS_COUNT];

    /* Target-specific and S2E additions. */
    struct {
        /* The KLEE ObjectState that backs the page in the current state, or
           NULL. libs2ecore owns the field (S2EExecutionStateTlb). */
        void *object_state;
    } extra;
} CPUTLBEntryFull;

/*
 * Data elements that are per MMU mode, minus the bits accessed by
 * the TCG fast path.
 */
typedef struct CPUTLBDesc {
    /*
     * Describe a region covering all of the large pages allocated
     * into the tlb.  When any page within this region is flushed,
     * we must flush the entire tlb.  The region is matched if
     * (addr & large_page_mask) == large_page_addr.
     */
    vaddr large_page_addr;
    vaddr large_page_mask;
    /* host time (in ns) at the beginning of the time window */
    int64_t window_begin_ns;
    /* maximum number of entries observed in the window */
    size_t window_max_entries;
    size_t n_used_entries;
    /* The next index to use in the tlb victim table.  */
    size_t vindex;
    /* The tlb victim table, in two parts.  */
    CPUTLBEntry vtable[CPU_VTLB_SIZE];
    CPUTLBEntryFull vfulltlb[CPU_VTLB_SIZE];
    /* Points at se_fulltlb below. */
    CPUTLBEntryFull *fulltlb;

    /* Backing store of f[i].table and of fulltlb (S2E). */
    CPUTLBEntry se_table[CPU_TLB_SIZE];
    CPUTLBEntryFull se_fulltlb[CPU_TLB_SIZE];
} CPUTLBDesc;

/*
 * Data elements that are shared between all MMU modes.
 */
typedef struct CPUTLBCommon {
    /* Upstream serializes TLB updates with this lock. libcpu has one vCPU
       and never takes it. */
    int lock;
    /*
     * Within dirty, for each bit N, modifications have been made to
     * mmu_idx N since the last time that mmu_idx was flushed.
     */
    MMUIdxMap dirty;
    /* Statistics. */
    size_t full_flush_count;
    size_t part_flush_count;
    size_t elide_flush_count;
} CPUTLBCommon;

/* The entire softmmu tlb, for all MMU modes. */
typedef struct CPUTLB {
    CPUTLBCommon c;
    CPUTLBDesc d[NB_MMU_MODES];
    CPUTLBDescFast f[NB_MMU_MODES];
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
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    /* Always true: libcpu has no icount mode. */
    bool can_do_io;
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
    /* Gives the accel/tcg code its cpu->cc->tcg_ops. Bitcode must not follow
       the pointer: the class is not registered with KLEE. */
    const CPUClass *cc;

    /* Fields that the accel/tcg code reads and that libcpu never changes. */
    bool created;
    bool ignore_memory_transaction_failures;

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

    /* Softmmu support: the return address into generated code of the memory
       access being handled, so that the MMIO and TB invalidation code can
       restore the CPU state without more arguments. */
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
