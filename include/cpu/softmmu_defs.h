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

#ifndef CONFIG_TCG_PASS_AREG0
uint8_t __ldb_mmu(target_ulong addr, int mmu_idx);
void __stb_mmu(target_ulong addr, uint8_t val, int mmu_idx);
uint16_t __ldw_mmu(target_ulong addr, int mmu_idx);
void __stw_mmu(target_ulong addr, uint16_t val, int mmu_idx);
uint32_t __ldl_mmu(target_ulong addr, int mmu_idx);
void __stl_mmu(target_ulong addr, uint32_t val, int mmu_idx);
uint64_t __ldq_mmu(target_ulong addr, int mmu_idx);
void __stq_mmu(target_ulong addr, uint64_t val, int mmu_idx);

uint8_t __ldb_cmmu(target_ulong addr, int mmu_idx);
void __stb_cmmu(target_ulong addr, uint8_t val, int mmu_idx);
uint16_t __ldw_cmmu(target_ulong addr, int mmu_idx);
void __stw_cmmu(target_ulong addr, uint16_t val, int mmu_idx);
uint32_t __ldl_cmmu(target_ulong addr, int mmu_idx);
void __stl_cmmu(target_ulong addr, uint32_t val, int mmu_idx);
uint64_t __ldq_cmmu(target_ulong addr, int mmu_idx);
void __stq_cmmu(target_ulong addr, uint64_t val, int mmu_idx);

uint8_t io_readb_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_mmu(target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_mmu(target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_mmu(target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_mmu(target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

uint8_t io_readb_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_cmmu(target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_cmmu(target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_cmmu(target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_cmmu(target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

void io_write_chkb_mmu_symb(target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
void io_write_chkw_mmu_symb(target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
void io_write_chkl_mmu_symb(target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
void io_write_chkq_mmu_symb(target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

void io_write_chkb_mmu(target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
void io_write_chkw_mmu(target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
void io_write_chkl_mmu(target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
void io_write_chkq_mmu(target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

uint8_t io_read_chkb_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint16_t io_read_chkw_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint32_t io_read_chkl_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint64_t io_read_chkq_mmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);

uint8_t io_read_chkb_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint16_t io_read_chkw_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint32_t io_read_chkl_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint64_t io_read_chkq_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);

uint8_t io_read_chkb_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint16_t io_read_chkw_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint32_t io_read_chkl_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
uint64_t io_read_chkq_cmmu(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);

#ifdef CONFIG_SYMBEX

uint8_t __ldb_mmu_symb(target_ulong addr, int mmu_idx);
void __stb_mmu_symb(target_ulong addr, uint8_t val, int mmu_idx);
uint16_t __ldw_mmu_symb(target_ulong addr, int mmu_idx);
void __stw_mmu_symb(target_ulong addr, uint16_t val, int mmu_idx);
uint32_t __ldl_mmu_symb(target_ulong addr, int mmu_idx);
void __stl_mmu_symb(target_ulong addr, uint32_t val, int mmu_idx);
uint64_t __ldq_mmu_symb(target_ulong addr, int mmu_idx);
void __stq_mmu_symb(target_ulong addr, uint64_t val, int mmu_idx);

#endif

#else
uint8_t helper_ldb_mmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val, int mmu_idx);
uint16_t helper_ldw_mmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx);
uint32_t helper_ldl_mmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx);
uint64_t helper_ldq_mmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx);

uint8_t helper_ldb_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stb_cmmu(CPUArchState *env, target_ulong addr, uint8_t val, int mmu_idx);
uint16_t helper_ldw_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stw_cmmu(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx);
uint32_t helper_ldl_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stl_cmmu(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx);
uint64_t helper_ldq_cmmu(CPUArchState *env, target_ulong addr, int mmu_idx);
void helper_stq_cmmu(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx);
#endif

uint8_t io_make_symbolicb_mmu(const char *name);
uint16_t io_make_symbolicw_mmu(const char *name);
uint32_t io_make_symbolicl_mmu(const char *name);
uint64_t io_make_symbolicq_mmu(const char *name);

uint8_t io_read_chk_symb_b_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint16_t io_read_chk_symb_w_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint32_t io_read_chk_symb_l_mmu(const char *label, target_ulong physaddr, uintptr_t pa);
uint64_t io_read_chk_symb_q_mmu(const char *label, target_ulong physaddr, uintptr_t pa);

#ifdef CONFIG_SYMBEX

uint8_t io_readb_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeb_mmu_symb(target_phys_addr_t physaddr, uint8_t val, target_ulong addr, void *retaddr);
uint16_t io_readw_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writew_mmu_symb(target_phys_addr_t physaddr, uint16_t val, target_ulong addr, void *retaddr);
uint32_t io_readl_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writel_mmu_symb(target_phys_addr_t physaddr, uint32_t val, target_ulong addr, void *retaddr);
uint64_t io_readq_mmu_symb(target_phys_addr_t physaddr, target_ulong addr, void *retaddr);
void io_writeq_mmu_symb(target_phys_addr_t physaddr, uint64_t val, target_ulong addr, void *retaddr);

uintptr_t se_notdirty_mem_write(target_phys_addr_t ram_addr);
uintptr_t se_notdirty_mem_read(target_phys_addr_t ram_addr);
#endif

#ifdef CONFIG_SYMBEX

uintptr_t se_notdirty_mem_write(target_phys_addr_t ram_addr);
uintptr_t se_notdirty_mem_read(target_phys_addr_t ram_addr);

#endif

#endif
