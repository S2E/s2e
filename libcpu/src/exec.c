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
#include <sys/mman.h>
#include <sys/types.h>

#include <cpu/ioport.h>
#include <cpu/memory.h>
#include <tcg/exec/tswap.h>
#include <tcg/tcg.h>
#include <utils/osdep.h>
#include "cpu.h"
#include "qemu-common.h"

#ifdef CONFIG_SYMBEX
#include <cpu-all.h>
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#endif
#include "exec-ram.h"
#include "exec-tb.h"
#include "exec.h"

// #define DEBUG_TB_INVALIDATE
// #define DEBUG_FLUSH
// #define DEBUG_TLB
// #define DEBUG_UNASSIGNED

/* make various TB consistency checks */
// #define DEBUG_TB_CHECK
// #define DEBUG_TLB_CHECK

// #define DEBUG_IOPORT
// #define DEBUG_SUBPAGE

/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK

CPUArchState *first_cpu, *cpu_single_env;

#ifdef CONFIG_SYMBEX
struct se_libcpu_interface_t g_sqi;

/* Nonzero while libs2ecore switches execution states. The TLB flush
   functions of accel/cputlb.c return without doing anything during that
   time, see se_tlb_flush_disabled(). */
int g_se_disable_tlb_flush = 0;
#endif

#ifdef CONFIG_SYMBEX
static uint32_t se_ldub_code(CPUArchState *env, target_ulong addr) {
    return cpu_ldub_code(env, addr);
}

static uint32_t se_ldl_code(CPUArchState *env, target_ulong addr) {
    return cpu_ldl_code(env, addr);
}
#endif

void cpu_exec_init_all(void) {
#ifdef CONFIG_SYMBEX
    g_sqi.libcpu.ldub_code = se_ldub_code;
    g_sqi.libcpu.ldl_code = se_ldl_code;
#endif
}

void cpu_exec_init(CPUArchState *env) {
    CPUState *cpu = env_cpu(env);

    /* libcpu emulates exactly one CPU. */
    assert(first_cpu == NULL);
    first_cpu = env;

    cpu->cpu_index = 0;
    cpu->cc = &g_x86_cpu_class;
    cpu->created = true;
    cpu->neg.can_do_io = true;
    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);

    tlb_init(cpu);
}

void cpu_common_reset(CPUState *cpu) {
    cpu->current_tb = NULL;
    cpu->se_current_tb = NULL;
    cpu->mem_io_pc = 0;
    cpu->translate_single_instruction = 0;
    cpu->halted = 0;
    cpu->interrupt_request = 0;
    cpu->exit_request = 0;
    cpu->se_tb_abort = 0;
}

/* mask must never be zero, except for A20 change call */
static void tcg_handle_interrupt(CPUArchState *env, int mask) {
    env_cpu(env)->interrupt_request |= mask;
}

CPUInterruptHandler cpu_interrupt_handler = tcg_handle_interrupt;

void cpu_reset_interrupt(CPUArchState *env, int mask) {
    env_cpu(env)->interrupt_request &= ~mask;
}

void cpu_exit(CPUArchState *env) {
    env_cpu(env)->exit_request = 1;
}

void cpu_abort(CPUArchState *env, const char *fmt, ...) {
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#ifdef TARGET_I386
    cpu_dump_state(env, stderr, fprintf, X86_DUMP_ALL);
#else
    cpu_dump_state(env, stderr, fprintf, 0);
#endif
    if (libcpu_log_enabled()) {
        libcpu_log("qemu: fatal: ");
        libcpu_log_vprintf(fmt, ap2);
        libcpu_log("\n");
#ifdef TARGET_I386
        log_cpu_state(env, X86_DUMP_ALL);
#else
        log_cpu_state(env, 0);
#endif
        libcpu_log_flush();
        libcpu_log_close();
    }
    va_end(ap2);
    va_end(ap);
    abort();
}

/* Note: start and end must be within the same ram block.  */
void cpu_physical_memory_reset_dirty(ram_addr_t start, ram_addr_t end, int dirty_flags) {
    CPUArchState *env;
    unsigned long length, start1;

    start &= TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    length = end - start;
    if (length == 0)
        return;
    cpu_physical_memory_mask_dirty_range(start, length, dirty_flags);

    /* we modify the TLB cache so that the dirty bit will be set again
       when accessing the range */
    start1 = (unsigned long) qemu_safe_ram_ptr(start);
    /* Check that we don't span multiple blocks - this breaks the
       address comparisons below.  */
    if ((unsigned long) qemu_safe_ram_ptr(end - 1) - start1 != (end - 1) - start) {
        abort();
    }

    env = first_cpu;
    if (env) {
        tlb_reset_dirty(env_cpu(env), start1, length);
    }
}

uintptr_t se_get_host_address(target_phys_addr_t paddr) {
    const MemoryDesc *sreg = mem_desc_find(paddr);
    if (!sreg) {
        return -1;
    }

    return sreg->kvm.userspace_addr + mem_desc_get_offset(sreg, paddr);
}

/* warning: addr must be aligned */
static inline uint32_t ldl_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint32_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        val = cpu_mmio_read(addr, 4);
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = ldl_raw(ptr);
    }

    return val;
}

uint32_t ldl_phys(target_phys_addr_t addr) {
    return ldl_phys_internal(addr);
}

/* warning: addr must be aligned */
static inline uint64_t ldq_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint64_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        /* I/O case */

        /* XXX This is broken when device endian != cpu endian.
               Fix and add "endian" variable check */
        val = cpu_mmio_read(addr, 4);
        val |= cpu_mmio_read(addr + 4, 4) << 32;
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = ldq_raw(ptr);
    }
    return val;
}

uint64_t ldq_phys(target_phys_addr_t addr) {
    return ldq_phys_internal(addr);
}

/* XXX: optimize */
uint32_t ldub_phys(target_phys_addr_t addr) {
    uint8_t val;
    cpu_physical_memory_read(addr, &val, 1);
    return val;
}

/* warning: addr must be aligned */
static inline uint32_t lduw_phys_internal(target_phys_addr_t addr) {
    uint8_t *ptr;
    uint64_t val;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        val = cpu_mmio_read(addr, 2);
    } else {
        /* RAM case */
        ptr = qemu_get_ram_ptr((sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr));
        val = lduw_raw(ptr);
    }
    return val;
}

uint32_t lduw_phys(target_phys_addr_t addr) {
    return lduw_phys_internal(addr);
}

/* warning: addr must be aligned. The ram page is not masked as dirty
   and the code inside is not invalidated. It is useful if the dirty
   bits are used to track modified PTEs */
void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 4);
    } else {
        unsigned long addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        ptr = qemu_get_ram_ptr(addr1);
        stl_raw(ptr, val);
    }
}

/* warning: addr must be aligned */
static inline void stl_phys_internal(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 4);
    } else {
        unsigned long addr1;
        addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        stl_raw(ptr, val);

        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 4, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stl_phys(target_phys_addr_t addr, uint32_t val) {
    stl_phys_internal(addr, val);
}

/* XXX: optimize */
void stb_phys(target_phys_addr_t addr, uint32_t val) {
    uint8_t v = val;
    cpu_physical_memory_write(addr, &v, 1);
}

/* warning: addr must be aligned */
static inline void stw_phys_internal(target_phys_addr_t addr, uint32_t val) {
    uint8_t *ptr;
    const MemoryDesc *sreg;

    sreg = mem_desc_find(addr);

    if (!sreg) {
        cpu_mmio_write(addr, val, 2);
    } else {
        unsigned long addr1;
        addr1 = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
        /* RAM case */
        ptr = qemu_get_ram_ptr(addr1);
        stw_raw(ptr, val);
        if (!cpu_physical_memory_is_dirty(addr1)) {
            /* invalidate code */
            tb_invalidate_phys_page_range(addr1, addr1 + 2, 0);
            /* set dirty bit */
            cpu_physical_memory_set_dirty_flags(addr1, (0xff & ~CODE_DIRTY_FLAG));
        }
    }
}

void stw_phys(target_phys_addr_t addr, uint32_t val) {
    stw_phys_internal(addr, val);
}

/* XXX: optimize */
void stq_phys(target_phys_addr_t addr, uint64_t val) {
    val = tswap64(val);
    cpu_physical_memory_write(addr, &val, 8);
}

void stq_le_phys(target_phys_addr_t addr, uint64_t val) {
    val = cpu_to_le64(val);
    cpu_physical_memory_write(addr, &val, 8);
}

void stq_be_phys(target_phys_addr_t addr, uint64_t val) {
    val = cpu_to_be64(val);
    cpu_physical_memory_write(addr, &val, 8);
}
