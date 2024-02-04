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

#ifndef __EXEC_TLB_H__

#define __EXEC_TLB_H__

static inline void tlb_set_dirty1(CPUTLBEntry *tlb_entry, target_ulong vaddr) {
#ifdef CONFIG_SYMBEX
    if ((tlb_entry->addr_write & ~TLB_SYMB) == (vaddr | TLB_NOTDIRTY)) {
#else
    if (tlb_entry->addr_write == (vaddr | TLB_NOTDIRTY)) {
#endif
        tlb_entry->addr_write &= ~TLB_NOTDIRTY;
    }
}

/* update the TLB corresponding to virtual page vaddr
   so that it is no longer dirty */
static inline void tlb_set_dirty(CPUArchState *env, target_ulong vaddr) {
    int i;
    int mmu_idx;

    vaddr &= TARGET_PAGE_MASK;
    i = (vaddr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        tlb_set_dirty1(&env->tlb_table[mmu_idx].table[i], vaddr);
    }
}

static bool tlb_is_dirty_ram(CPUTLBEntry *tlbe) {
    return (tlbe->addr_write & (TLB_INVALID_MASK | TLB_MMIO | TLB_NOTDIRTY)) == 0;
}

static inline void tlb_reset_dirty_range(CPUTLBEntry *tlb_entry, unsigned long start, unsigned long length) {
    unsigned long addr;
    if (tlb_is_dirty_ram(tlb_entry)) {
        addr = (tlb_entry->addr_write & TARGET_PAGE_MASK) + tlb_entry->addend;
        if ((addr - start) < length) {
            tlb_entry->addr_write |= TLB_NOTDIRTY;
        }
    }
}

#ifdef CONFIG_SYMBEX
int tlb_is_dirty(CPUArchState *env, target_ulong vaddr);
#endif

#endif
