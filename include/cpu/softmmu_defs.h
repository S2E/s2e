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

/*
 *  Software MMU support
 *
 * Declare helpers used by TCG for qemu_ld/st ops.
 *
 * Used by softmmu_exec.h, TCG targets and exec-all.h.
 *
 */
#ifndef SOFTMMU_DEFS_H
#define SOFTMMU_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SYMBEX
uintptr_t se_notdirty_mem_write(target_phys_addr_t ram_addr, int size);
uintptr_t se_notdirty_mem_read(target_phys_addr_t ram_addr);
#endif

#if defined(CONFIG_SYMBEX_MP) || defined(STATIC_TRANSLATOR)
uint8_t helper_ldb_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stb_mmu_symb(CPUArchState *env, target_ulong addr, uint8_t val, int mmu_idx, void *retaddr);
uint16_t helper_ldw_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stw_mmu_symb(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx, void *retaddr);
uint32_t helper_ldl_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stl_mmu_symb(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx, void *retaddr);
uint64_t helper_ldq_mmu_symb(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stq_mmu_symb(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx, void *retaddr);

uint8_t io_make_symbolicb_mmu(const char *name);
uint16_t io_make_symbolicw_mmu(const char *name);
uint32_t io_make_symbolicl_mmu(const char *name);
uint64_t io_make_symbolicq_mmu(const char *name);

uint8_t io_read_chk_symb_b_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint16_t io_read_chk_symb_w_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint32_t io_read_chk_symb_l_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint64_t io_read_chk_symb_q_mmu(const char *label, target_ulong physaddr, uintptr_t pa);

uint8_t io_readb_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_mmu_symb(CPUArchState *env, target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

#endif

uint8_t helper_ldb_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val, int mmu_idx, void *retaddr);
uint16_t helper_ldw_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx, void *retaddr);
uint32_t helper_ldl_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx, void *retaddr);
uint64_t helper_ldq_mmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx, void *retaddr);

uint8_t helper_ldb_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stb_cmmu(CPUArchState *env, target_ulong addr, uint8_t val, int mmu_idx, void *retaddr);
uint16_t helper_ldw_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stw_cmmu(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx, void *retaddr);
uint32_t helper_ldl_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stl_cmmu(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx, void *retaddr);
uint64_t helper_ldq_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);
void helper_stq_cmmu(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx, void *retaddr);

uint8_t io_readb_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

uint8_t io_readb_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_cmmu(CPUArchState *env, target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_cmmu(CPUArchState *env, target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_cmmu(CPUArchState *env, target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_cmmu(CPUArchState *env, target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

void io_write_chkb_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
void io_write_chkw_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
void io_write_chkl_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
void io_write_chkq_mmu(CPUArchState *env, target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

uint8_t io_read_chkb_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint16_t io_read_chkw_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint32_t io_read_chkl_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint64_t io_read_chkq_mmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);

uint8_t io_read_chkb_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint16_t io_read_chkw_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint32_t io_read_chkl_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint64_t io_read_chkq_cmmu(CPUArchState *env, target_phys_addr_t physaddr, target_ulong addr, void *retaddr);

#ifdef __cplusplus
}
#endif

#endif
