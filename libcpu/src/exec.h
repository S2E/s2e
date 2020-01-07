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

#ifndef __EXEC__H__

#define __EXEC__H__

#include <cpu/exec.h>
#include <cpu/memory.h>
#include "target-i386/cpu.h"

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
#define L1_MAP_ADDR_SPACE_BITS HOST_LONG_BITS
#else
#define L1_MAP_ADDR_SPACE_BITS TARGET_PHYS_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define L2_BITS 10
#define L2_SIZE (1 << L2_BITS)

#define P_L2_LEVELS (((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / L2_BITS) + 1)

/* The bits remaining after N lower levels of page tables.  */
#define V_L1_BITS_REM ((L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)

#if V_L1_BITS_REM < 4
#define V_L1_BITS (V_L1_BITS_REM + L2_BITS)
#else
#define V_L1_BITS V_L1_BITS_REM
#endif

#define V_L1_SIZE ((target_ulong) 1 << V_L1_BITS)

#define V_L1_SHIFT (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - V_L1_BITS)

#define SMC_BITMAP_USE_THRESHOLD 10

void tlb_protect_code(ram_addr_t ram_addr);
void tlb_unprotect_code_phys(CPUArchState *env, ram_addr_t ram_addr, target_ulong vaddr);

const MemoryDesc *phys_page_find(target_phys_addr_t index);

extern const struct MemoryDescOps watch_mem_ops;

#endif
