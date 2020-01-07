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

#include <cpu/config.h>
#include <cpu/memdbg.h>
#include <cpu/memory.h>
#include <inttypes.h>
#include <tcg/utils/osdep.h>
#include "qemu-common.h"

#include <cpu/ioport.h>
#include "exec.h"

/* used for ROM loading : can write in RAM and ROM */
static void cpu_physical_memory_write_rom(target_phys_addr_t addr, const uint8_t *buf, int len) {
    int l;
    uint8_t *ptr;
    target_phys_addr_t page;
    const MemoryDesc *sreg;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;

        sreg = mem_desc_find(page);

        if (!sreg) {
            /* do nothing */
        } else {
            unsigned long addr1;
            addr1 = sreg->ram_addr + mem_desc_get_offset(sreg, addr);
            /* ROM/RAM case */
            ptr = qemu_get_ram_ptr(addr1);
#ifdef CONFIG_SYMBEX
            int i;
            for (i = 0; i < l; ++i)
                stb_raw(ptr + i, buf[i]);
#else
            memcpy(ptr, buf, l);
#endif
            qemu_put_ram_ptr(ptr);
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write) {
    int l;
    uint8_t *ptr;
    uint32_t val;
    target_phys_addr_t page;
    const MemoryDesc *sreg;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        sreg = mem_desc_find(page);

        if (is_write) {
            if (!sreg) {
                target_phys_addr_t addr1;
                addr1 = addr;
                /* XXX: could force cpu_single_env to NULL to avoid
                   potential bugs */
                if (l >= 4 && ((addr1 & 3) == 0)) {
                    /* 32 bit write access */
                    val = ldl_p(buf);
                    cpu_mmio_write(addr1, val, 4);
                    l = 4;
                } else if (l >= 2 && ((addr1 & 1) == 0)) {
                    /* 16 bit write access */
                    val = lduw_p(buf);
                    cpu_mmio_write(addr1, val, 2);
                    l = 2;
                } else {
                    /* 8 bit write access */
                    val = ldub_p(buf);
                    cpu_mmio_write(addr1, val, 1);
                    l = 1;
                }
            } else {
                ram_addr_t addr1;
                addr1 = sreg->ram_addr + mem_desc_get_offset(sreg, addr);
                /* RAM case */
                ptr = qemu_get_ram_ptr(addr1);
#ifdef CONFIG_SYMBEX
                g_sqi.mem.dma_write((uintptr_t) ptr, buf, l);
#else
                memcpy(ptr, buf, l);
#endif
                if (!cpu_physical_memory_is_dirty(addr1)) {
                    /* invalidate code */
                    tb_invalidate_phys_page_range(addr1, addr1 + l, 0);
                    /* set dirty bit */
                    cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
                }
                qemu_put_ram_ptr(ptr);
            }
        } else {
            if (!sreg) {
                target_phys_addr_t addr1 = addr;
                /* I/O case */
                if (l >= 4 && ((addr1 & 3) == 0)) {
                    /* 32 bit read access */
                    val = cpu_mmio_read(addr1, 4);
                    stl_p(buf, val);
                    l = 4;
                } else if (l >= 2 && ((addr1 & 1) == 0)) {
                    /* 16 bit read access */
                    val = cpu_mmio_read(addr1, 2);
                    stw_p(buf, val);
                    l = 2;
                } else {
                    /* 8 bit read access */
                    val = cpu_mmio_read(addr1, 1);
                    stb_p(buf, val);
                    l = 1;
                }
            } else {
                /* RAM case */
                ptr = qemu_get_ram_ptr(sreg->ram_addr + mem_desc_get_offset(sreg, addr));
#ifdef CONFIG_SYMBEX
                g_sqi.mem.dma_read((uintptr_t) ptr, buf, l);
#else
                memcpy(buf, ptr, l);
#endif
                qemu_put_ram_ptr(ptr);
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

/* virtual memory access for debug (includes writing to ROM) */
int cpu_memory_rw_debug(void *opaque_env, target_ulong addr, uint8_t *buf, int len, int is_write) {
    int l;
    target_phys_addr_t phys_addr;
    target_ulong page;
    CPUArchState *env = (CPUArchState *) opaque_env;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write)
            cpu_physical_memory_write_rom(phys_addr, buf, l);
        else
            cpu_physical_memory_rw(phys_addr, buf, l, is_write);
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

void cpu_host_memory_rw(uintptr_t source, uintptr_t dest, int length, int is_write) {
    if (is_write) {
        for (unsigned i = 0; i < length; ++i) {
            stb_raw((void *) (dest + i), *(uint8_t *) (source + i));
        }

        ram_addr_t addr1;

        if (qemu_ram_addr_from_host((void *) dest, &addr1)) {
            /* This may happen if attempting to write to not yet mapped memory */
            return;
        }

        uint64_t access_len = length;
        while (access_len) {
            unsigned l;
            l = TARGET_PAGE_SIZE;
            if (l > access_len)
                l = access_len;
            if (!cpu_physical_memory_is_dirty(addr1)) {
                /* invalidate code */
                tb_invalidate_phys_page_range(addr1, addr1 + l, 0);
                /* set dirty bit */
                cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
            }
            addr1 += l;
            access_len -= l;
        }
    } else {
        for (unsigned i = 0; i < length; ++i) {
            *(uint8_t *) (dest + i) = ldub_raw((uint8_t *) (source + i));
        }
    }
}
