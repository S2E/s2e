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

#ifndef __LIBCPU_EXEC_H__

#define __LIBCPU_EXEC_H__

#include <cpu/config.h>
#include <cpu/i386/cpu.h>
#include <cpu/interrupt.h>
#include <cpu/softmmu_defs.h>
#include <cpu/tb.h>
#include <libcpu-compiler.h>
#include <libcpu-log.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The return address may point to the start of the next instruction.
   Subtracting one gets us the call instruction itself.  */
#if defined(CONFIG_TCG_INTERPRETER)
/* Alpha and SH4 user mode emulations and Softmmu call GETPC().
   For all others, GETPC remains undefined (which makes TCI a little faster. */
#if defined(CONFIG_SOFTMMU) || defined(TARGET_ALPHA) || defined(TARGET_SH4)
extern void *tci_tb_ptr;
#define GETPC() tci_tb_ptr
#endif
#elif defined(__s390__) && !defined(__s390x__)
#define GETPC() ((void *) (((uintptr_t) __builtin_return_address(0) & 0x7fffffffUL) - 1))
#elif defined(__arm__)
/* Thumb return addresses have the low bit set, so we need to subtract two.
   This is still safe in ARM mode because instructions are 4 bytes.  */
#define GETPC() ((void *) ((uintptr_t) __builtin_return_address(0) - 2))
#else
#if defined(SYMBEX_LLVM_LIB)
#define GETPC() 0
#else
#define GETPC() (((uintptr_t) __builtin_return_address(0) - 1))
#endif
#endif

/* The true return address will often point to a host insn that is part of
   the next translated guest insn.  Adjust the address backward to point to
   the middle of the call insn.  Subtracting one would do the job except for
   several compressed mode architectures (arm, mips) which set the low bit
   to indicate the compressed mode; subtracting two works around that.  It
   is also the case that there are no host isas that contain a call insn
   smaller than 4 bytes, so we don't worry about special-casing this.  */
#define GETPC_ADJ 2

#include "precise-pc.h"

void cpu_exit(CPUArchState *s);
void cpu_exec_init_all(void);
void tcg_exec_init(unsigned long tb_size);

void tlb_flush(CPUArchState *env, int flush_global);
void tlb_flush_page(CPUArchState *env, target_ulong addr);
void tlb_fill(CPUArchState *env1, target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx, void *retaddr);

void tb_flush(CPUArchState *env);

/* page related stuff */

#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)
#define TARGET_PAGE_ALIGN(addr) (((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)

bool init_ram_size(int argc, char **argv);

uint64_t get_ram_size(void);
void *get_ram_list_phys_dirty(void);
uint64_t get_ram_list_phys_dirty_size(void);
ram_addr_t last_ram_offset(void);

void cpu_dump_state(CPUArchState *env, FILE *f, fprintf_function cpu_fprintf, int flags);
void cpu_dump_statistics(CPUArchState *env, FILE *f, fprintf_function cpu_fprintf, int flags);

/* Return the physical page corresponding to a virtual one. Use it
   only for debugging because no protection checks are done. Return -1
   if no page found. */
target_phys_addr_t cpu_get_phys_page_debug(CPUArchState *env, target_ulong addr);

void LIBCPU_NORETURN cpu_abort(CPUArchState *env, const char *fmt, ...) GCC_FMT_ATTR(2, 3);
extern CPUArchState *first_cpu, *cpu_single_env;

typedef void (*CPUInterruptHandler)(CPUArchState *, int);
extern CPUInterruptHandler cpu_interrupt_handler;

void LIBCPU_NORETURN cpu_loop_exit(CPUArchState *env1);
void LIBCPU_NORETURN cpu_loop_exit_restore(CPUArchState *env1, uintptr_t ra);

#define VGA_DIRTY_FLAG 0x01
#define CODE_DIRTY_FLAG 0x02

void cpu_physical_memory_get_dirty_bitmap(uint8_t *bitmap, ram_addr_t start, int length, int dirty_flags);

void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end, int dirty_flags);

const struct MemoryDescOps *phys_get_ops(target_phys_addr_t index);
bool is_notdirty_ops(const struct MemoryDescOps *ops);

#ifdef CONFIG_SYMBEX
bool se_ismemfunc(const struct MemoryDescOps *ops, int isWrite);
#endif

#ifdef __cplusplus
}
#endif

#endif
