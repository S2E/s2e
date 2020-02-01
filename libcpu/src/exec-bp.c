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

#include <glib.h>

#include <cpu/config.h>
#include <cpu/memory.h>
#include <tcg/tcg.h>
#include <tcg/utils/osdep.h>
#include "exec.h"
#include "qemu-common.h"

#if defined(TARGET_HAS_ICE)
static void breakpoint_invalidate(CPUArchState *env, target_ulong pc) {
    target_phys_addr_t addr;
    ram_addr_t ram_addr;

    addr = cpu_get_phys_page_debug(env, pc);
    const MemoryDesc *sreg = mem_desc_find(addr);
    if (!sreg) {
        return;
    }

    ram_addr = (sreg->ram_addr & TARGET_PAGE_MASK) + mem_desc_get_offset(sreg, addr);
    tb_invalidate_phys_page_range(ram_addr, ram_addr + 1, 0);
}
#endif /* TARGET_HAS_ICE */

/* Add a watchpoint.  */
int cpu_watchpoint_insert(CPUArchState *env, target_ulong addr, target_ulong len, int flags,
                          CPUWatchpoint **watchpoint) {
    target_ulong len_mask = ~(len - 1);
    CPUWatchpoint *wp;

    /* sanity checks: allow power-of-2 lengths, deny unaligned watchpoints */
    if ((len & (len - 1)) || (addr & ~len_mask) || len == 0 || len > TARGET_PAGE_SIZE) {
        fprintf(stderr, "qemu: tried to set invalid watchpoint at " TARGET_FMT_lx ", len=" TARGET_FMT_lu "\n", addr,
                len);
        return -EINVAL;
    }
    wp = g_malloc(sizeof(*wp));

    wp->vaddr = addr;
    wp->len_mask = len_mask;
    wp->flags = flags;

    /* keep all GDB-injected watchpoints in front */
    if (flags & BP_GDB)
        QTAILQ_INSERT_HEAD(&env->watchpoints, wp, entry);
    else
        QTAILQ_INSERT_TAIL(&env->watchpoints, wp, entry);

    tlb_flush_page(env, addr);

    if (watchpoint)
        *watchpoint = wp;
    return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUArchState *env, target_ulong addr, target_ulong len, int flags) {
    target_ulong len_mask = ~(len - 1);
    CPUWatchpoint *wp;

    QTAILQ_FOREACH (wp, &env->watchpoints, entry) {
        if (addr == wp->vaddr && len_mask == wp->len_mask && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
            cpu_watchpoint_remove_by_ref(env, wp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUArchState *env, CPUWatchpoint *watchpoint) {
    QTAILQ_REMOVE(&env->watchpoints, watchpoint, entry);

    tlb_flush_page(env, watchpoint->vaddr);

    g_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUArchState *env, int mask) {
    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &env->watchpoints, entry, next) {
        if (wp->flags & mask)
            cpu_watchpoint_remove_by_ref(env, wp);
    }
}

/* Add a breakpoint.  */
int cpu_breakpoint_insert(CPUArchState *env, target_ulong pc, int flags, CPUBreakpoint **breakpoint) {
#if defined(TARGET_HAS_ICE)
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = pc;
    bp->flags = flags;

    /* keep all GDB-injected breakpoints in front */
    if (flags & BP_GDB)
        QTAILQ_INSERT_HEAD(&env->breakpoints, bp, entry);
    else
        QTAILQ_INSERT_TAIL(&env->breakpoints, bp, entry);

    breakpoint_invalidate(env, pc);

    if (breakpoint)
        *breakpoint = bp;
    return 0;
#else
    return -ENOSYS;
#endif
}

/* Remove a specific breakpoint.  */
int cpu_breakpoint_remove(CPUArchState *env, target_ulong pc, int flags) {
#if defined(TARGET_HAS_ICE)
    CPUBreakpoint *bp;

    QTAILQ_FOREACH (bp, &env->breakpoints, entry) {
        if (bp->pc == pc && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(env, bp);
            return 0;
        }
    }
    return -ENOENT;
#else
    return -ENOSYS;
#endif
}

/* Remove a specific breakpoint by reference.  */
void cpu_breakpoint_remove_by_ref(CPUArchState *env, CPUBreakpoint *breakpoint) {
#if defined(TARGET_HAS_ICE)
    QTAILQ_REMOVE(&env->breakpoints, breakpoint, entry);

    breakpoint_invalidate(env, breakpoint->pc);

    g_free(breakpoint);
#endif
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUArchState *env, int mask) {
#if defined(TARGET_HAS_ICE)
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &env->breakpoints, entry, next) {
        if (bp->flags & mask)
            cpu_breakpoint_remove_by_ref(env, bp);
    }
#endif
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUArchState *env, int enabled) {
#if defined(TARGET_HAS_ICE)
    if (env->singlestep_enabled != enabled) {
        env->singlestep_enabled = enabled;

        /* must flush all the translated code to avoid inconsistencies */
        /* XXX: only flush what is necessary */
        tb_flush(env);
    }
#endif
}

/* Generate a debug exception if a watchpoint has been hit.  */
static void check_watchpoint(int offset, int len_mask, int flags) {
    CPUArchState *env = cpu_single_env;
    target_ulong pc, cs_base;
    TranslationBlock *tb;
    target_ulong vaddr;
    CPUWatchpoint *wp;
    int cpu_flags;

    if (env->watchpoint_hit) {
        /* We re-entered the check after replacing the TB. Now raise
         * the debug interrupt so that is will trigger after the
         * current instruction. */
        cpu_interrupt(env, CPU_INTERRUPT_DEBUG);
        return;
    }

#ifdef CONFIG_SYMBEX
    vaddr = (g_sqi.mem.read_mem_io_vaddr(1)) + offset;
#else
    vaddr = (env->mem_io_vaddr & TARGET_PAGE_MASK) + offset;
#endif

    QTAILQ_FOREACH (wp, &env->watchpoints, entry) {
        if ((vaddr == (wp->vaddr & len_mask) || (vaddr & wp->len_mask) == wp->vaddr) && (wp->flags & flags)) {
            wp->flags |= BP_WATCHPOINT_HIT;
            if (!env->watchpoint_hit) {
                env->watchpoint_hit = wp;
                tb = tcg_tb_lookup(env->mem_io_pc);
                if (!tb) {
                    cpu_abort(env,
                              "check_watchpoint: could not find TB for "
                              "pc=%p",
                              (void *) env->mem_io_pc);
                }
                cpu_restore_state(env, env->mem_io_pc);
                tb_phys_invalidate(tb, -1);
                if (wp->flags & BP_STOP_BEFORE_ACCESS) {
                    env->exception_index = EXCP_DEBUG;
                    cpu_loop_exit(env);
                } else {
                    cpu_get_tb_cpu_state(env, &pc, &cs_base, &cpu_flags);
                    tb_gen_code(env, pc, cs_base, cpu_flags, 1);
                    cpu_resume_from_signal(env, NULL);
                }
            }
        } else {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }
}

/* Watchpoint access routines.  Watchpoints are inserted using TLB tricks,
   so these check for a hit then pass through to the normal out-of-line
   phys routines.  */
static uint64_t watch_mem_read(target_phys_addr_t addr, unsigned size) {
    check_watchpoint(addr & ~TARGET_PAGE_MASK, ~(size - 1), BP_MEM_READ);
    switch (size) {
        case 1:
            return ldub_phys(addr);
        case 2:
            return lduw_phys(addr);
        case 4:
            return ldl_phys(addr);
        default:
            abort();
    }
}

static void watch_mem_write(target_phys_addr_t addr, uint64_t val, unsigned size) {
    check_watchpoint(addr & ~TARGET_PAGE_MASK, ~(size - 1), BP_MEM_WRITE);
    switch (size) {
        case 1:
            stb_phys(addr, val);
            break;
        case 2:
            stw_phys(addr, val);
            break;
        case 4:
            stl_phys(addr, val);
            break;
        default:
            abort();
    }
}

const struct MemoryDescOps watch_mem_ops = {
    .read = watch_mem_read,
    .write = watch_mem_write,
};
