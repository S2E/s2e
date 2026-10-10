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

/// @file
/// Returns the MMU index of the current CPU mode.
///
/// Upstream's header of the same name calls cpu->cc->tcg_ops->mmu_index().
/// This version computes the index directly. The accessors of cpu-ldst.h
/// inline it into helpers that also run as bitcode inside KLEE, where the
/// tcg_ops table cannot be read (it is not registered as a KLEE object).

#ifndef S2E_CPU_MMU_INDEX_H
#define S2E_CPU_MMU_INDEX_H

#include <cpu/i386/cpu.h>

/// @param cpu the CPU
/// @param ifetch true for a code fetch. x86 uses the same index for code and
///        data until the 11.1 frontend arrives.
/// @return the MMU index for the current privilege level
static inline int cpu_mmu_index(CPUState *cpu, bool ifetch) {
    return x86_mmu_index(cpu_env(cpu));
}

#endif
