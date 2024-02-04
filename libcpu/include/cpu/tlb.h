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

#include <tcg/tlb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_TLB_BITS 10
#define CPU_TLB_SIZE (1 << CPU_TLB_BITS)

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
#define CPU_IOTLB_CHECK target_phys_addr_t iotlb_ramaddr[NB_MMU_MODES][CPU_TLB_SIZE];
#else
#define CPU_IOTLB_CHECK
#endif

#define CPU_COMMON_TLB                                                \
    /* The meaning of the MMU modes is defined in the target code. */ \
    CPUTLBDescFast tlb_table[NB_MMU_MODES];                           \
    CPUTLBEntry _tlb_table[NB_MMU_MODES][CPU_TLB_SIZE];               \
    target_phys_addr_t iotlb[NB_MMU_MODES][CPU_TLB_SIZE];             \
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

#ifdef __cplusplus
}
#endif

#endif
