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

#ifndef __LIBCPU_COMMON_H__

#define __LIBCPU_COMMON_H__

#include <cpu/tb.h>
#include <cpu/tlb.h>
#include <cpu/types.h>
#include <qqueue.h>
#include <setjmp.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CPUBreakpoint {
    target_ulong pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

typedef struct CPUWatchpoint {
    target_ulong vaddr;
    target_ulong len_mask;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
} CPUWatchpoint;

#define CPU_TEMP_BUF_NLONGS 128
#define CPU_COMMON                                                                                    \
    int se_common_start;                    /* Dummy variable to mark the start of the common area */ \
    struct TranslationBlock *current_tb;    /* currently executing TB  */                             \
    struct TranslationBlock *se_current_tb; /* currently executing TB  */                             \
    /* soft mmu support */                                                                            \
    /* in order to avoid passing too many arguments to the MMIO                                       \
       helpers, we store some rarely used information in the CPU                                      \
       context) */                                                                                    \
    unsigned long mem_io_pc;   /* host pc at which the memory was                                     \
                                  accessed */                                                         \
    target_ulong mem_io_vaddr; /* target virtual addr at which the                                    \
                                     memory was accessed */                                           \
    /* When set, this forces the translator to put only one instruction in the next TB.               \
     * This variable is automatically reset before code execution */                                  \
    uint32_t translate_single_instruction;                                                            \
    uint32_t halted; /* Nonzero if the CPU is in suspend state */                                     \
    uint32_t interrupt_request;                                                                       \
    volatile sig_atomic_t exit_request;                                                               \
    CPU_COMMON_TLB                                                                                    \
    CPU_COMMON_PHYSRAM_TLB                                                                            \
    CPUTLBEntry *se_tlb_current;                                                                      \
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];                                         \
    /* buffer for temporaries in the code generator */                                                \
    long temp_buf[CPU_TEMP_BUF_NLONGS];                                                               \
    /* Used to handle self-modifying code */                                                          \
    unsigned restored_instruction_size;                                                               \
                                                                                                      \
    /* from this point: preserved by CPU reset */                                                     \
    /* ice debug support */                                                                           \
    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;                                         \
    int singlestep_enabled;                                                                           \
                                                                                                      \
    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;                                         \
    CPUWatchpoint *watchpoint_hit;                                                                    \
                                                                                                      \
    /* Core interrupt code */                                                                         \
    jmp_buf jmp_env;                                                                                  \
    int exception_index;                                                                              \
                                                                                                      \
    CPUArchState *next_cpu; /* next CPU sharing TB cache */                                           \
    int cpu_index;          /* CPU index (informative) */                                             \
    int numa_node;          /* NUMA node this cpu is belonging to  */                                 \
    int running;            /* Nonzero if cpu is currently running(usermode).  */                     \
    /* user data */                                                                                   \
    void *opaque;                                                                                     \
    unsigned size; /* Size of this structure */                                                       \
                                                                                                      \
    uint32_t created;                                                                                 \
    uint32_t stop;     /* Stop request */                                                             \
    int generate_llvm; /* Generate LLVM code during translation */                                    \
    int se_common_end; /* Dummy variable to mark the end of the common area */

#ifdef __cplusplus
}
#endif

#endif
