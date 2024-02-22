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

#ifndef _EXEC_ALL_H_
#define _EXEC_ALL_H_

#include "qemu-common.h"

/* allow to see translation results - the slowdown should be negligible, so we leave it */
#define DEBUG_DISAS

#include "exec-ram.h"

#include <cpu/tb.h>

struct cpu_stats_t {
    uint64_t tb_hits;
    uint64_t tb_misses;
    uint64_t tb_regens;
    uint64_t tb_unlinks;
};

extern struct cpu_stats_t g_cpu_stats;

/* is_jmp field values */
#define DISAS_NEXT    0 /* next instruction can be analyzed */
#define DISAS_JUMP    1 /* only pc was modified dynamically */
#define DISAS_UPDATE  2 /* cpu state was modified dynamically */
#define DISAS_TB_JUMP 3 /* only pc was modified statically */

#ifdef STATIC_TRANSLATOR
/* Accomodate large TBs */
#define OPC_BUF_SIZE 640000
#else
#define OPC_BUF_SIZE 640
#endif

#define OPC_MAX_SIZE (OPC_BUF_SIZE - MAX_OP_PER_INSTR)

/* Maximum size a TCG op can expand to.  This is complicated because a
   single op may require several host instructions and register reloads.
   For now take a wild guess at 192 bytes, which should allow at least
   a couple of fixup instructions per argument.  */
#define TCG_MAX_OP_SIZE 192

#define OPPARAM_BUF_SIZE (OPC_BUF_SIZE * MAX_OPC_PARAM)

void gen_intermediate_code(CPUArchState *env, struct TranslationBlock *tb);
void gen_intermediate_code_pc(CPUArchState *env, struct TranslationBlock *tb);

#ifdef CONFIG_SYMBEX
void cpu_gen_flush(void);
void cpu_gen_init_opc(void);
void se_restore_state_to_opc(CPUX86State *env, TranslationBlock *tb, target_ulong pc, int cc_op, target_ulong next_pc);
#endif

void restore_state_to_opc(CPUArchState *env, struct TranslationBlock *tb, target_ulong *data);

int restore_state_to_next_pc(CPUX86State *env, TranslationBlock *tb);

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb);

void LIBCPU_NORETURN cpu_resume_from_signal(CPUArchState *env1, void *puc);
void LIBCPU_NORETURN cpu_io_recompile(CPUArchState *env, void *retaddr);
TranslationBlock *tb_gen_code(CPUArchState *env, target_ulong pc, target_ulong cs_base, int flags, int cflags);
void cpu_exec_init(CPUArchState *env);
int page_unprotect(target_ulong address, uintptr_t pc, void *puc);
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end, int is_cpu_write_access);

void tlb_set_page(CPUArchState *env, target_ulong vaddr, target_phys_addr_t paddr, int prot, int mmu_idx,
                  target_ulong size);

#define CODE_GEN_ALIGN 16 /* must be >= of the size of a icache line */

#define CODE_GEN_PHYS_HASH_BITS 15
#define CODE_GEN_PHYS_HASH_SIZE (1 << CODE_GEN_PHYS_HASH_BITS)

/* estimated block size for TB allocation */
/* XXX: use a per code average code fragment size and modulate it
   according to the host CPU */
#if defined(CONFIG_SOFTMMU)
#define CODE_GEN_AVG_BLOCK_SIZE 128
#else
#define CODE_GEN_AVG_BLOCK_SIZE 64
#endif

#include <cpu/tb.h>

static inline unsigned int tb_jmp_cache_hash_page(target_ulong pc) {
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK;
}

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc) {
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK) | (tmp & TB_JMP_ADDR_MASK));
}

static inline unsigned int tb_phys_hash_func(tb_page_addr_t pc) {
    return (pc >> 2) & (CODE_GEN_PHYS_HASH_SIZE - 1);
}

extern TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];

#include <tcg/utils/spinlock.h>

extern spinlock_t tb_lock;

extern int tb_invalidated_flag;

#include <cpu/exec.h>

#include <cpu/softmmu_defs.h>
#include <cpu/tlb.h>

#define ACCESS_TYPE (NB_MMU_MODES + 1)
#define MEMSUFFIX   _code

#define DATA_SIZE 1
#include "softmmu_header.h"

#define DATA_SIZE 2
#include "softmmu_header.h"

#define DATA_SIZE 4
#include "softmmu_header.h"

#define DATA_SIZE 8
#include "softmmu_header.h"

#undef ACCESS_TYPE
#undef MEMSUFFIX
#undef env

tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr);

typedef void(CPUDebugExcpHandler)(CPUArchState *env);

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler);

#endif
