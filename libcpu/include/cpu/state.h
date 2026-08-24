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
 * CPUState holds only the CPU caches for now: the TLB, the RAM TLB and the
 * TB jump cache, moved out of CPUX86State so that they stop being part of
 * the snapshotted execution state (tlb-update.md). The execution-state fields
 * of upstream's CPUState (exception_index, interrupt_request, jmp_env, ...)
 * migrate here from CPUX86State during the port (PORTING.md phase 4).
 *
 * The TLB keeps the QEMU 1.0 organization (fixed size, iotlb, no victim TLB,
 * no CPUTLBEntryFull); upstream's algorithms arrive with the cputlb.c import
 * (PORTING.md phase 2).
 *
 * This header is included at the end of cpu/i386/cpu.h: ArchCPU embeds
 * CPUArchState by value, so the complete CPUX86State must be visible first.
 */

#include <stddef.h>
#include <stdint.h>

#include <utils/compiler.h>

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
 */
typedef struct CPUState {
    /* Replaces upstream's cpu->cc->tcg_ops; wired up when the 11.1 accel/tcg
       code lands (PORTING.md 3.1). */
    const struct TCGCPUOps *tcg_ops;

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

#ifdef __cplusplus
}
#endif

#endif
