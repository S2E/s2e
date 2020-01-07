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

#ifndef __LIB_CPU_TLB_H__

#define __LIB_CPU_TLB_H__

#include <cpu/config.h>
#include <cpu/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_TLB_BITS 10
#define CPU_TLB_SIZE (1 << CPU_TLB_BITS)

#if HOST_LONG_BITS == 32 && TARGET_LONG_BITS == 32
#define CPU_TLB_ENTRY_BITS 6
#else
#define CPU_TLB_ENTRY_BITS 6
#endif

typedef struct CPUTLBEntry {
    /* bit TARGET_LONG_BITS to TARGET_PAGE_BITS : virtual address
       bit TARGET_PAGE_BITS-1..4  : Nonzero for accesses that should not
                                    go directly to ram.
       bit 3                      : indicates that the entry is invalid
       bit 2..0                   : zero
    */
    target_ulong addr_read;
    target_ulong addr_write;
    target_ulong addr_code;
    target_ulong pad1;

    /* Addend to virtual address to get host address.  IO accesses
       use the corresponding iotlb value.  */
    uintptr_t addend;

#ifdef CONFIG_SYMBEX
    uintptr_t se_addend;
    void *objectState;

    /* padding to get a power of two size */
    uint8_t dummy[(1 << CPU_TLB_ENTRY_BITS) - (sizeof(target_ulong) * 4 + 3 * sizeof(uintptr_t))];
#else
    uint8_t dummy[(1 << CPU_TLB_ENTRY_BITS) - (sizeof(target_ulong) * 4 + 1 * sizeof(uintptr_t))];
#endif
} CPUTLBEntry;

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
#define CPU_IOTLB_CHECK target_phys_addr_t iotlb_ramaddr[NB_MMU_MODES][CPU_TLB_SIZE];
#else
#define CPU_IOTLB_CHECK
#endif

extern int CPUTLBEntry_wrong_size[sizeof(CPUTLBEntry) == (1 << CPU_TLB_ENTRY_BITS) ? 1 : -1];

#define CPU_COMMON_TLB                                                \
    /* The meaning of the MMU modes is defined in the target code. */ \
    CPUTLBEntry *tlb_table[NB_MMU_MODES];                             \
    CPUTLBEntry _tlb_table[NB_MMU_MODES][CPU_TLB_SIZE];               \
    target_phys_addr_t iotlb[NB_MMU_MODES][CPU_TLB_SIZE];             \
    uintptr_t tlb_mask[NB_MMU_MODES];                                 \
    CPU_IOTLB_CHECK                                                   \
    target_ulong tlb_flush_addr;                                      \
    target_ulong tlb_flush_mask;

typedef struct CPUTLBRAMEntry {
    uintptr_t host_page;
    uintptr_t addend;
    void *object_state;
} CPUTLBRAMEntry;

#if defined(SE_ENABLE_PHYSRAM_TLB)
#define CPU_COMMON_PHYSRAM_TLB CPUTLBRAMEntry se_ram_tlb[CPU_TLB_SIZE];
#else
#define CPU_COMMON_PHYSRAM_TLB
#endif

/* Flags stored in the low bits of the TLB virtual address.  These are
 * defined so that fast path ram access is all zeros.
 * The flags all must be between TARGET_PAGE_BITS and
 * maximum address alignment bit.
 */
/* Zero if TLB entry is valid.  */
#define TLB_INVALID_MASK (1 << (TARGET_PAGE_BITS - 1))
/* Set if TLB entry references a clean RAM page.  The iotlb entry will
   contain the page physical address.  */
#define TLB_NOTDIRTY (1 << (TARGET_PAGE_BITS - 2))
/* Set if TLB entry is an IO callback.  */
#define TLB_MMIO (1 << (TARGET_PAGE_BITS - 3))
/* Set if TLB entry must have MMU lookup repeated for every access */
#define TLB_RECHECK (1 << (TARGET_PAGE_BITS - 4))

#ifdef CONFIG_SYMBEX
/* Set if TLB entry points to a page that has symbolic data */
#define TLB_SYMB (1 << (TARGET_PAGE_BITS - 5))

/* Set if TLB entry points to a page that does not belong to us (only for write) */
#define TLB_NOT_OURS (1 << (TARGET_PAGE_BITS - 6))

#endif

/* Indicates that accesses to the page must be traced */
#define TLB_MEM_TRACE (1 << (TARGET_PAGE_BITS - 7))

/* Use this mask to check interception with an alignment mask
 * in a TCG backend.
 */
#ifdef CONFIG_SYMBEX
#define TLB_FLAGS_MASK (TLB_INVALID_MASK | TLB_NOTDIRTY | TLB_MMIO | TLB_SYMB | TLB_RECHECK | TLB_NOT_OURS)
#else
#define TLB_FLAGS_MASK (TLB_INVALID_MASK | TLB_NOTDIRTY | TLB_MMIO | TLB_RECHECK)
#endif

#ifdef __cplusplus
}
#endif

#endif
