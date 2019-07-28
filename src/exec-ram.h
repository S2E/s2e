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

#ifndef __EXEC_RAM_H__

#define __EXEC_RAM_H__

#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <cpu/se_libcpu.h>
#include <cpu/types.h>
#include <inttypes.h>
#include "qqueue.h"

#define RAM_ADDR_MAX UINTPTR_MAX
#define RAM_ADDR_FMT "%" PRIxPTR

/* memory API */
/* This should only be used for ram local to a device.  */
void *qemu_get_ram_ptr(ram_addr_t addr);
/* This is a helper function that can be called from gdb */
void *get_ram_ptr_internal(ram_addr_t addr);
void *qemu_ram_ptr_length(ram_addr_t addr, ram_addr_t *size);
/* Same but slower, to use for migration, where the order of
 * RAMBlocks must not change. */
void *qemu_safe_ram_ptr(ram_addr_t addr);
void qemu_put_ram_ptr(void *addr);
/* This should not be used by devices.  */
int qemu_ram_addr_from_host(void *ptr, ram_addr_t *ram_addr);
ram_addr_t qemu_ram_addr_from_host_nofail(void *ptr);

ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host);
void qemu_ram_free_from_ptr(ram_addr_t addr);

/* memory API */

typedef struct RAMBlock {
    uint8_t *host;
    ram_addr_t offset;
    ram_addr_t length;
} RAMBlock;

typedef struct RAMList {
    uint8_t *phys_dirty;
    uint64_t phys_dirty_size;
    RAMBlock *blocks;
    unsigned block_count;
} RAMList;
extern RAMList ram_list;

#ifdef CONFIG_SYMBEX
static inline void se_write_dirty_mask_fast(uintptr_t addr, uint8_t value) {
#if defined(SE_ENABLE_FAST_DIRTYMASK)
    uint64_t actual = addr + g_se_dirty_mask_addend;
    *(uint8_t *) actual = value;
#else
    g_sqi.mem.write_dirty_mask(addr, value);
#endif
}

static inline int se_read_dirty_mask_fast(uintptr_t addr) {
#if defined(SE_ENABLE_FAST_DIRTYMASK)
    uint64_t actual = addr + g_se_dirty_mask_addend;
    return *(uint8_t *) actual;
#else
    return g_sqi.mem.read_dirty_mask(addr);
#endif
}
#endif

/* read dirty bit (return 0 or 1) */
static inline int cpu_physical_memory_is_dirty(ram_addr_t addr) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    return se_read_dirty_mask_fast((uint64_t) &ram_list.phys_dirty[addr >> TARGET_PAGE_BITS]) == 0xff;
#else
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] == 0xff;
#endif
}

static inline int cpu_physical_memory_get_dirty_flags(ram_addr_t addr) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    return se_read_dirty_mask_fast((uint64_t) &ram_list.phys_dirty[addr >> TARGET_PAGE_BITS]);
#else
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS];
#endif
}

static inline void cpu_physical_memory_set_dirty(ram_addr_t addr) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    se_write_dirty_mask_fast((uint64_t) &ram_list.phys_dirty[addr >> TARGET_PAGE_BITS], 0xff);
#else
    ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] = 0xff;
#endif
}

static inline int cpu_physical_memory_set_dirty_flags(ram_addr_t addr, int dirty_flags) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    int flags = se_read_dirty_mask_fast((uint64_t) &ram_list.phys_dirty[addr >> TARGET_PAGE_BITS]);
    flags |= dirty_flags;
    se_write_dirty_mask_fast((uint64_t) &ram_list.phys_dirty[addr >> TARGET_PAGE_BITS], flags);
    return flags;
#else
    return ram_list.phys_dirty[addr >> TARGET_PAGE_BITS] |= dirty_flags;
#endif
}

static inline void cpu_physical_memory_mask_dirty_range(ram_addr_t start, int length, int dirty_flags) {
    int i, mask, len;
    uint8_t *p;
    ram_addr_t end = TARGET_PAGE_ALIGN(start + length);
    len = (end - start) >> TARGET_PAGE_BITS;
    mask = ~dirty_flags;
    p = ram_list.phys_dirty + (start >> TARGET_PAGE_BITS);
    for (i = 0; i < len; i++) {
#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
        int flags = se_read_dirty_mask_fast((uint64_t) &p[i]);
        flags &= mask;
        se_write_dirty_mask_fast((uint64_t) &p[i], flags);
#else
        p[i] &= mask;
#endif
    }
}

#endif
