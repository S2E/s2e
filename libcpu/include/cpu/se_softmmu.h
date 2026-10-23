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
/// The native softmmu functions that libs2ecore uses.
///
/// The softmmu (src/accel/cputlb.c) is compiled natively and as LLVM bitcode.
/// The bitcode copy keeps the access path and calls the native copy for
/// everything that reaches device models, the dirty bitmap or the translation
/// block cache. libs2ecore registers these native functions with KLEE so that
/// the bitcode can call them, and its own memory access handlers
/// (MMUFunctionHandlers.cpp) call them too.

#ifndef S2E_CPU_SE_SOFTMMU_H
#define S2E_CPU_SE_SOFTMMU_H

#include <cpu/i386/cpu.h>
#include <tcg/tcg-memopidx.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Records a store to a page that may hold translated code, and invalidates
/// the translation blocks that the store overwrites.
void notdirty_write(CPUState *cpu, vaddr mem_vaddr, unsigned size, CPUTLBEntryFull *full, uintptr_t retaddr);

/// Reads up to 8 bytes from a device, most significant byte first, and
/// appends them to ret_be.
uint64_t do_ld_mmio_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t ret_be, vaddr addr, int size, int mmu_idx,
                        MMUAccessType type, uintptr_t ra);

/// Writes the low size bytes of val_le to a device, least significant byte
/// first, and returns the remaining bytes.
uint64_t do_st_mmio_leN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t val_le, vaddr addr, int size, int mmu_idx,
                        uintptr_t ra);

/// Raises a debug exception if the access hits a watchpoint.
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len, MemTxAttrs attrs, int flags, uintptr_t ra);

/// Fills the TLB for one page, or raises the guest exception if the access
/// faults and probe is false.
bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size, MMUAccessType access_type, int mmu_idx, bool probe,
                      uintptr_t retaddr);

/// The native guest memory accessors. ra is 0 when the caller is not
/// generated code.
uint8_t cpu_ldb_mmu(CPUArchState *env, vaddr ptr, MemOpIdx oi, uintptr_t ra);
uint16_t cpu_ldw_mmu(CPUArchState *env, vaddr ptr, MemOpIdx oi, uintptr_t ra);
uint32_t cpu_ldl_mmu(CPUArchState *env, vaddr ptr, MemOpIdx oi, uintptr_t ra);
uint64_t cpu_ldq_mmu(CPUArchState *env, vaddr ptr, MemOpIdx oi, uintptr_t ra);

void cpu_stb_mmu(CPUArchState *env, vaddr ptr, uint8_t val, MemOpIdx oi, uintptr_t ra);
void cpu_stw_mmu(CPUArchState *env, vaddr ptr, uint16_t val, MemOpIdx oi, uintptr_t ra);
void cpu_stl_mmu(CPUArchState *env, vaddr ptr, uint32_t val, MemOpIdx oi, uintptr_t ra);
void cpu_stq_mmu(CPUArchState *env, vaddr ptr, uint64_t val, MemOpIdx oi, uintptr_t ra);

#ifdef __cplusplus
}
#endif

#endif
