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
#include <utils/osdep.h>
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
        QTAILQ_INSERT_HEAD(&env_cpu(env)->watchpoints, wp, entry);
    else
        QTAILQ_INSERT_TAIL(&env_cpu(env)->watchpoints, wp, entry);

    tlb_flush_page(env_cpu(env), addr);

    if (watchpoint)
        *watchpoint = wp;
    return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUArchState *env, target_ulong addr, target_ulong len, int flags) {
    target_ulong len_mask = ~(len - 1);
    CPUWatchpoint *wp;

    QTAILQ_FOREACH (wp, &env_cpu(env)->watchpoints, entry) {
        if (addr == wp->vaddr && len_mask == wp->len_mask && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
            cpu_watchpoint_remove_by_ref(env, wp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUArchState *env, CPUWatchpoint *watchpoint) {
    QTAILQ_REMOVE(&env_cpu(env)->watchpoints, watchpoint, entry);

    tlb_flush_page(env_cpu(env), watchpoint->vaddr);

    g_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUArchState *env, int mask) {
    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &env_cpu(env)->watchpoints, entry, next) {
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
        QTAILQ_INSERT_HEAD(&env_cpu(env)->breakpoints, bp, entry);
    else
        QTAILQ_INSERT_TAIL(&env_cpu(env)->breakpoints, bp, entry);

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

    QTAILQ_FOREACH (bp, &env_cpu(env)->breakpoints, entry) {
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
    QTAILQ_REMOVE(&env_cpu(env)->breakpoints, breakpoint, entry);

    breakpoint_invalidate(env, breakpoint->pc);

    g_free(breakpoint);
#endif
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUArchState *env, int mask) {
#if defined(TARGET_HAS_ICE)
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &env_cpu(env)->breakpoints, entry, next) {
        if (bp->flags & mask)
            cpu_breakpoint_remove_by_ref(env, bp);
    }
#endif
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUArchState *env, int enabled) {
#if defined(TARGET_HAS_ICE)
    if (env_cpu(env)->singlestep_enabled != enabled) {
        env_cpu(env)->singlestep_enabled = enabled;

        /* must flush all the translated code to avoid inconsistencies */
        /* XXX: only flush what is necessary */
        tb_flush(env);
    }
#endif
}

/* Returns the length of the range that a watchpoint covers. */
static inline vaddr watchpoint_len(const CPUWatchpoint *wp) {
    return (vaddr) (target_ulong) ~wp->len_mask + 1;
}

static inline bool watchpoint_address_matches(const CPUWatchpoint *wp, vaddr addr, vaddr len) {
    /* Compare the last bytes of the two ranges instead of their ends, so
       that a range that ends at the top of the address space does not wrap
       around to zero. */
    vaddr wpend = wp->vaddr + watchpoint_len(wp) - 1;
    vaddr addrend = addr + len - 1;

    return !(addr > wpend || wp->vaddr > addrend);
}

/* Returns the flags of the watchpoints that overlap [addr, addr + len).
   tlb_set_page_full() calls it to decide whether accesses to a page must
   take the slow path (TLB_WATCHPOINT). */
int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len) {
    CPUWatchpoint *wp;
    int ret = 0;

    QTAILQ_FOREACH (wp, &cpu->watchpoints, entry) {
        if (watchpoint_address_matches(wp, addr, len)) {
            ret |= wp->flags;
        }
    }
    return ret;
}

/* Generates a debug exception if the access hits a watchpoint. The softmmu
   calls it for accesses to pages that carry TLB_WATCHPOINT. ra is the return
   address of the access into generated code. */
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len, MemTxAttrs attrs, int flags, uintptr_t ra) {
    CPUArchState *env = cpu_env(cpu);
    target_ulong pc, cs_base;
    TranslationBlock *tb;
    CPUWatchpoint *wp;
    int cpu_flags;

    if (cpu->watchpoint_hit) {
        /* We re-entered the check after replacing the TB. Now raise
         * the debug interrupt so that is will trigger after the
         * current instruction. */
        cpu_interrupt(env, CPU_INTERRUPT_DEBUG);
        return;
    }

    QTAILQ_FOREACH (wp, &cpu->watchpoints, entry) {
        if ((wp->flags & flags) && watchpoint_address_matches(wp, addr, len)) {
            wp->flags |= BP_WATCHPOINT_HIT;
            if (!cpu->watchpoint_hit) {
                cpu->watchpoint_hit = wp;
                tb = tcg_tb_lookup(ra);
                if (!tb) {
                    cpu_abort(env,
                              "check_watchpoint: could not find TB for "
                              "pc=%p",
                              (void *) ra);
                }
                cpu_restore_state(env, ra);
                tb_phys_invalidate(tb, -1);
                if (wp->flags & BP_STOP_BEFORE_ACCESS) {
                    cpu->exception_index = EXCP_DEBUG;
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
