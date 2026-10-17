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
/// Everything that src/accel/cputlb.c needs from the rest of QEMU and that
/// libcpu does not have yet.
///
/// cputlb.c is upstream's softmmu. It expects QEMU's memory API, its physical
/// memory dirty tracking, its multi-CPU work queues, its plugin interface and
/// its trace points. This header provides each of them in the smallest form
/// that keeps the imported file close to upstream's text:
///
///  - The memory API is a set of inline functions over MemoryDesc
///    (cpu/memory.h). A region is either RAM, backed by a MemoryDesc, or MMIO,
///    which is forwarded to cpu_mmio_read() and cpu_mmio_write().
///  - Dirty tracking maps onto the one-byte-per-page mask of exec-ram.h.
///  - libcpu has one vCPU, so work that upstream queues on another CPU runs
///    in place and the TLB lock is not taken.
///  - Plugins, tracing, icount and record/replay do not exist. Their entry
///    points compile to nothing.
///
/// Only cputlb.c includes this header. Each section disappears when the
/// upstream code it stands in for is imported.

#ifndef S2E_CPUTLB_DEPS_H
#define S2E_CPUTLB_DEPS_H

#include <glib.h>
#include <string.h>

#include <cpu/config.h>

#include <utils/atomic.h>
#include <utils/atomic128.h>
#include <utils/host-utils.h>
#include <utils/int128.h>
#include <utils/osdep.h>

#include "cpu.h"

// clang-format off
#include <tcg/tcg.h>
#include <tcg/tcg-ldst.h>
#include <tcg/accel/getpc.h>
#include <tcg/exec/helper-proto-common.h>
#include <tcg/utils/bswap.h>
// clang-format on

#include <cpu/accel/cpu-ldst-common.h>
#include <cpu/accel/cpu-mmu-index.h>
#include <cpu/accel/cpu-ops.h>
#include <cpu/accel/probe.h>
#include <cpu/exec/cputlb.h>
#include <cpu/exec/page-protection.h>
#include <cpu/exec/tlb-flags.h>
#include <cpu/ioport.h>
#include <cpu/memory.h>
#include <timer.h>

#include "cpu-all.h"
#include "exec-all.h"
#include "exec-ram.h"
#include "exec-tb.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#include <tcg/tcg-s2e.h>
#endif

/*
 * Logging and tracing.
 */

#define CPU_LOG_MMU                                 0
#define qemu_log_mask(mask, ...)                    libcpu_log_mask(mask, __VA_ARGS__)
#define error_report(fmt, ...)                      fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define trace_memory_notdirty_write_access(a, b, c) ((void) 0)
#define trace_memory_notdirty_set_dirty(a)          ((void) 0)

/*
 * One vCPU, one thread. The TLB lock is never taken, and work that upstream
 * queues on a CPU runs immediately on the calling one.
 */

#define qemu_spin_init(l)    ((void) (l))
#define qemu_spin_destroy(l) ((void) (l))
#define qemu_spin_lock(l)    ((void) (l))
#define qemu_spin_unlock(l)  ((void) (l))

#define qemu_cpu_is_self(cpu) true

typedef union {
    int host_int;
    unsigned long host_ulong;
    void *host_ptr;
    vaddr target_ptr;
} run_on_cpu_data;

#define RUN_ON_CPU_HOST_INT(i)   ((run_on_cpu_data) {.host_int = (i)})
#define RUN_ON_CPU_HOST_PTR(p)   ((run_on_cpu_data) {.host_ptr = (p)})
#define RUN_ON_CPU_TARGET_PTR(v) ((run_on_cpu_data) {.target_ptr = (v)})

typedef void (*run_on_cpu_func)(CPUState *cpu, run_on_cpu_data data);

/* There is no other CPU to iterate over. */
#define CPU_FOREACH(cpu) for ((cpu) = NULL; false;)

static inline void async_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data) {
    func(cpu, data);
}

static inline void async_safe_run_on_cpu(CPUState *cpu, run_on_cpu_func func, run_on_cpu_data data) {
    func(cpu, data);
}

/* Upstream asks whether other vCPUs may run concurrently, to decide how much
   atomicity a load or store needs. */
static inline bool cpu_in_serial_context(CPUState *cpu) {
    return true;
}

/* x86 guests on x86 hosts need no memory barrier (upstream: backend-ldst.h). */
#define cpu_req_mo(cpu, type) ((void) 0)

/* x86 has one address space. */
#define cpu_asidx_from_attrs(cpu, attrs) 0

/* The global lock that serializes device emulation. MMIO is dispatched on
   the vCPU thread, which already owns the device state. */
#define BQL_LOCK_GUARD() ((void) 0)

/* Guards the page table of user-mode emulation. */
#define WITH_MMAP_LOCK_GUARD()

/* Upstream leaves the CPU loop to redo an access with all other vCPUs
   stopped when it cannot give the required atomicity. There are no other
   vCPUs, so the access never needs it. */
#define cpu_loop_exit_atomic(cpu, ra) abort()

#define trace_load_atom16_or_exit_fallback(ra) ((void) 0)
#define trace_store_atom2_fallback(p, ra)      ((void) 0)
#define trace_store_atom4_fallback(p, ra)      ((void) 0)
#define trace_store_atom8_fallback(p, ra)      ((void) 0)
#define trace_store_atom16_fallback(p, ra)     ((void) 0)

/*
 * icount. libcpu never restricts I/O to the last instruction of a TB, so
 * neg.can_do_io is always true and this function is never reached.
 */
#undef cpu_io_recompile
#define cpu_io_recompile(cpu, ra) abort()

/*
 * Plugins.
 */

enum qemu_plugin_mem_rw {
    QEMU_PLUGIN_MEM_R = 1,
    QEMU_PLUGIN_MEM_W,
    QEMU_PLUGIN_MEM_RW,
};

static inline bool cpu_plugin_mem_cbs_enabled(const CPUState *cpu) {
    return false;
}

static inline void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr, uint64_t value_low, uint64_t value_high,
                                           MemOpIdx oi, enum qemu_plugin_mem_rw rw) {
}

/*
 * TB jump cache. The cache is still QEMU 1.0's array in neg; upstream's
 * CPUJumpCache arrives with cpu-exec.c.
 */

static inline void tcg_flush_jmp_cache(CPUState *cpu) {
    memset(cpu->neg.tb_jmp_cache, 0, sizeof(cpu->neg.tb_jmp_cache));
}

/*
 * TB invalidation.
 */

/*
 * Invalidates the TBs that a store of size bytes at ram_addr overwrites.
 *
 * The QEMU 1.0 function finds the TB that is doing the store through
 * mem_io_pc, to stop it if it overwrites its own code. It tests the store
 * against one byte of the bitmap of code bytes, which covers 8 bytes of the
 * page, so the store is split where it crosses a multiple of 8. The old
 * softmmu only called it for aligned accesses; upstream's does not align.
 */
static inline void tb_invalidate_phys_range_fast(CPUState *cpu, ram_addr_t ram_addr, unsigned size, uintptr_t retaddr) {
    cpu->mem_io_pc = retaddr;
    while (size) {
        unsigned len = MIN(size, 8 - (unsigned) (ram_addr & 7));
        tb_invalidate_phys_page_fast(ram_addr, len);
        ram_addr += len;
        size -= len;
    }
}

/*
 * Watchpoints. Defined in exec-bp.c over the QEMU 1.0 watchpoint list.
 */

int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len);
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len, MemTxAttrs attrs, int flags, uintptr_t ra);

/*
 * Memory API. See cpu/memory.h for MemoryRegion and MemoryRegionSection.
 */

#define MEMTX_OK 0

/* Looks up the section of a guest physical page. For RAM, *xlat is the offset
   of the page inside the region. For MMIO, it is the guest physical address,
   which is what cpu_mmio_read() and cpu_mmio_write() take. */
static inline MemoryRegionSection *address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr,
                                                                     hwaddr *xlat, hwaddr *plen, MemTxAttrs attrs,
                                                                     int *prot) {
    const MemoryDesc *desc = mem_desc_find(addr);
    if (!desc) {
        *xlat = addr;
        return &g_mmio_section;
    }

    *xlat = mem_desc_get_offset(desc, addr);
    return (MemoryRegionSection *) &desc->section;
}

static inline bool memory_region_is_ram(MemoryRegion *mr) {
    return mr->desc != NULL;
}

/* A ROM device is read like RAM and written like MMIO. libcpu has none. */
static inline bool memory_region_is_romd(MemoryRegion *mr) {
    return false;
}

static inline void *memory_region_get_ram_ptr(MemoryRegion *mr) {
    return (void *) (uintptr_t) mr->desc->kvm.userspace_addr;
}

static inline ram_addr_t memory_region_get_ram_addr(MemoryRegion *mr) {
    return mr->desc->ram_addr & TARGET_PAGE_MASK;
}

/*
 * cpu_mmio_read() and cpu_mmio_write() exchange values with the device model
 * in little-endian byte order, which is the guest's. The caller states the
 * byte order it wants in op: the softmmu asks for big-endian values when it
 * reads and passes little-endian values when it writes. Upstream's memory
 * API converts between the two, and so must these functions.
 *
 * The device interface takes accesses of 1, 2 or 4 bytes. An 8-byte access is
 * done as two 4-byte ones, low half first, as the QEMU 1.0 softmmu did.
 */
static inline uint64_t se_mmio_adjust_endianness(uint64_t value, MemOp op) {
    if ((op & MO_BSWAP) == MO_LE) {
        return value;
    }

    switch (op & MO_SIZE) {
        case MO_8:
            return value;
        case MO_16:
            return bswap16(value);
        case MO_32:
            return bswap32(value);
        case MO_64:
            return bswap64(value);
        default:
            g_assert_not_reached();
    }
}

static inline MemTxResult memory_region_dispatch_read(MemoryRegion *mr, hwaddr addr, uint64_t *pval, MemOp op,
                                                      MemTxAttrs attrs) {
    uint64_t value;

    if (memop_size(op) == 8) {
        value = cpu_mmio_read(addr, 4);
        value |= cpu_mmio_read(addr + 4, 4) << 32;
    } else {
        value = cpu_mmio_read(addr, memop_size(op));
    }

    *pval = se_mmio_adjust_endianness(value, op);
    return MEMTX_OK;
}

static inline MemTxResult memory_region_dispatch_write(MemoryRegion *mr, hwaddr addr, uint64_t data, MemOp op,
                                                       MemTxAttrs attrs) {
    data = se_mmio_adjust_endianness(data, op);

    if (memop_size(op) == 8) {
        cpu_mmio_write(addr, (uint32_t) data, 4);
        cpu_mmio_write(addr + 4, data >> 32, 4);
    } else {
        cpu_mmio_write(addr, data, memop_size(op));
    }
    return MEMTX_OK;
}

/*
 * Dirty tracking. Upstream keeps one bitmap per client. libcpu keeps one byte
 * per page, with one bit per client (exec-ram.h), and the byte reads 0xff
 * when the page needs no more tracking.
 */

#define DIRTY_MEMORY_CODE    CODE_DIRTY_FLAG
#define DIRTY_CLIENTS_NOCODE (0xff & ~CODE_DIRTY_FLAG)

static inline bool physical_memory_is_clean(ram_addr_t addr) {
    return !cpu_physical_memory_is_dirty(addr);
}

static inline bool physical_memory_get_dirty_flag(ram_addr_t addr, unsigned client) {
    return (cpu_physical_memory_get_dirty_flags(addr) & client) != 0;
}

static inline void physical_memory_set_dirty_flag(ram_addr_t addr, unsigned client) {
    cpu_physical_memory_set_dirty_flags(addr, client);
}

static inline void physical_memory_set_dirty_range(ram_addr_t start, ram_addr_t length, uint8_t mask) {
    ram_addr_t end = TARGET_PAGE_ALIGN(start + length);
    for (ram_addr_t addr = start & TARGET_PAGE_MASK; addr < end; addr += TARGET_PAGE_SIZE) {
        cpu_physical_memory_set_dirty_flags(addr, mask);
    }
}

/* Clears the flags of a client and makes the TLB send the next store to each
   of these pages through notdirty_write(). cpu_physical_memory_reset_dirty()
   does both: it ends in tlb_reset_dirty(). */
static inline bool physical_memory_test_and_clear_dirty(ram_addr_t start, ram_addr_t length, unsigned client,
                                                        void *unused) {
    cpu_physical_memory_reset_dirty(start, start + length, client);
    return true;
}

/*
 * S2E hooks.
 *
 * libs2ecore keeps, for every KLEE object that backs a guest page, the list
 * of TLB entries that refer to it (S2EExecutionStateTlb). It needs the list
 * to repoint the entries when KLEE copies the object. The functions below
 * tell libs2ecore when an entry is filled or dropped. cputlb.c calls them
 * unconditionally; they compile to nothing in builds without symbolic
 * execution and in the bitcode build, which never fills or flushes the TLB.
 */

#if defined(CONFIG_SYMBEX) && !defined(SYMBEX_LLVM_LIB)

extern int g_se_disable_tlb_flush;

/* libs2ecore sets the guard while it saves and restores the device state on
   a state switch. A flush requested during that time is dropped: the switch
   ends with a full flush. */
static inline bool se_tlb_flush_disabled(void) {
    return g_se_disable_tlb_flush != 0;
}

/* Called before entry (mmu_idx, index) is overwritten or invalidated. */
static inline void se_tlb_drop_entry(CPUState *cpu, int mmu_idx, uintptr_t index) {
    CPUTLBEntryFull *full = &cpu->neg.tlb.d[mmu_idx].fulltlb[index];

    if (full->extra.object_state) {
        g_sqi.tlb.flush_tlb_cache_page(full->extra.object_state, mmu_idx, index);
        full->extra.object_state = NULL;
    }
}

/* Called before all the entries of one MMU index are invalidated. Upstream's
   flush clears the fast table only, so the object pointers of the full
   entries are cleared here. */
static inline void se_tlb_drop_mmuidx(CPUState *cpu, int mmu_idx) {
    CPUTLBDesc *desc = &cpu->neg.tlb.d[mmu_idx];
    size_t n = (cpu_tlb_fast(cpu, mmu_idx)->mask >> CPU_TLB_ENTRY_BITS) + 1;

#if defined(SE_ENABLE_TLB)
    if (!*g_sqi.mode.single_path_mode) {
        g_sqi.tlb.flush_tlb_cache_mmuidx(mmu_idx);
    }
#endif

    for (size_t i = 0; i < n; i++) {
        desc->fulltlb[i].extra.object_state = NULL;
    }
}

/* Called after the entry for addr_page has been written. host_page is the
   host address of the page, or 0 for MMIO, which has no KLEE object. */
static inline void se_tlb_set_entry(CPUState *cpu, int mmu_idx, vaddr addr_page, uintptr_t host_page) {
    cpu_tlb_fast(cpu, mmu_idx)
        ->table[(addr_page >> TARGET_PAGE_BITS) & (cpu_tlb_fast(cpu, mmu_idx)->mask >> CPU_TLB_ENTRY_BITS)]
        .se_addend = 0;

#if defined(SE_ENABLE_TLB) && defined(CONFIG_SYMBEX_MP)
    if (host_page) {
        g_sqi.tlb.update_tlb_entry(cpu_env(cpu), mmu_idx, addr_page, host_page);
    }
#endif
}

/* Adds the S2E flags that are known when an entry is filled. They apply to
   loads and stores, not to code fetches. */
static inline void se_tlb_fill_flags(hwaddr paddr_page, unsigned *read_flags, unsigned *write_flags) {
    if (*g_sqi.events.before_memory_access_signals_count || *g_sqi.events.after_memory_access_signals_count) {
        *read_flags |= TLB_MEM_TRACE;
        *write_flags |= TLB_MEM_TRACE;
    }

#if defined(CONFIG_SYMBEX_MP)
    if (g_sqi.mem.is_mmio_symbolic(paddr_page, TARGET_PAGE_SIZE)) {
        *read_flags |= TLB_SYMB_MMIO;
        *write_flags |= TLB_SYMB_MMIO;
    }
#endif
}

#else

#define se_tlb_flush_disabled()                           false
#define se_tlb_drop_entry(cpu, mmu_idx, index)            ((void) 0)
#define se_tlb_drop_mmuidx(cpu, mmu_idx)                  ((void) 0)
#define se_tlb_set_entry(cpu, mmu_idx, addr, host)        ((void) 0)
#define se_tlb_fill_flags(paddr, read_flags, write_flags) ((void) 0)

#endif

/*
 * The bitcode build.
 *
 * cputlb.c is also compiled to LLVM bitcode, which KLEE interprets when the
 * guest computes on symbolic data. In that build the address of an access
 * can be symbolic. Three things follow.
 *
 * The TLB must be indexed with a concrete value, or KLEE would treat the
 * lookup as a symbolic pointer into the TLB. SE_CONCRETE_PAGE() forks the
 * state on the page number, which leaves the offset in the page symbolic.
 *
 * The target hooks must be the bitcode copies. A call through cpu->cc->tcg_ops
 * reaches the native ones, and KLEE forks once per possible value of each
 * symbolic argument of a native function. SE_TCG_OP() calls the x86 function
 * by name instead. The ops table itself is native memory that KLEE cannot
 * read, so SE_TCG_HAS_OP() answers for it: x86 has the hooks that SE_TCG_OP()
 * is used for, and no tlb_fill_align.
 *
 * The functions that reach device models or the TB cache stay native. Their
 * definitions carry SE_NATIVE in place of static, which exports them so that
 * the bitcode can call them, and their bodies are compiled out of the
 * bitcode. Their prototypes are below.
 */

#if defined(SYMBEX_LLVM_LIB)

#define SE_TCG_HAS_OP(ops, op) false
#define SE_TCG_OP(cpu, op)     glue(x86_cpu_, op)

#define SE_CONCRETE_PAGE(page) tcg_llvm_fork_and_concretize(page, 0, ((target_ulong) - 1) >> TARGET_PAGE_BITS, 0)

/*
 * The bitcode is optimized for size, which inlines less. tlb_index() and
 * tlb_entry() are on the TLB hit path of every access, and KLEE pushes a stack
 * frame for each call. They are defined before the always_inline region that
 * cputlb-symbex.c.inc starts, so they carry the attribute themselves.
 */
#define SE_ALWAYS_INLINE __attribute__((always_inline))

/* The victim TLB is disabled and always empty (tlb_set_page_full()). */
#define victim_tlb_hit(cpu, mmu_idx, index, access_type, page) false

#else

#define SE_TCG_HAS_OP(ops, op) ((ops)->op != NULL)
#define SE_TCG_OP(cpu, op)     ((cpu)->cc->tcg_ops->op)
#define SE_CONCRETE_PAGE(page) (page)
#define SE_ALWAYS_INLINE

#endif

#if defined(CONFIG_SYMBEX)

#define SE_NATIVE

void notdirty_write(CPUState *cpu, vaddr mem_vaddr, unsigned size, CPUTLBEntryFull *full, uintptr_t retaddr);
uint64_t do_ld_mmio_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t ret_be, vaddr addr, int size, int mmu_idx,
                        MMUAccessType type, uintptr_t ra);
Int128 do_ld16_mmio_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t ret_be, vaddr addr, int size, int mmu_idx,
                        uintptr_t ra);
uint64_t do_st_mmio_leN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t val_le, vaddr addr, int size, int mmu_idx,
                        uintptr_t ra);
uint64_t do_st16_mmio_leN(CPUState *cpu, CPUTLBEntryFull *full, Int128 val_le, vaddr addr, int size, int mmu_idx,
                          uintptr_t ra);

#else

#define SE_NATIVE static

#endif

#endif
