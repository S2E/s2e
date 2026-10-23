/*
 * softmmu size bounds
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_TLB_BOUNDS_H
#define ACCEL_TCG_TLB_BOUNDS_H

/*
 * S2E: the three bounds are equal, which pins the size of the TLB. The tables
 * are static arrays that libs2ecore registers once with KLEE, so they cannot
 * be reallocated. tlb_mmu_resize_locked() then always finds that the new
 * size equals the old one and returns.
 */
#define CPU_TLB_DYN_MIN_BITS     CPU_TLB_BITS
#define CPU_TLB_DYN_MAX_BITS     CPU_TLB_BITS
#define CPU_TLB_DYN_DEFAULT_BITS CPU_TLB_BITS

#endif /* ACCEL_TCG_TLB_BOUNDS_H */
