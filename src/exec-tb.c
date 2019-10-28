/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2019  Cyberhaven
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
#include <glib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <cpu/types.h>
#include <tcg/tcg.h>
#include <tcg/utils/osdep.h>
#include "cpu.h"
#include "qemu-common.h"

#include "exec-phystb.h"
#include "exec.h"

#ifdef CONFIG_SYMBEX
#include <cpu-all.h>
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#endif

#include "exec-tb.h"

TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];

/* any access to the tbs or the page table must use this lock */
spinlock_t tb_lock = SPIN_LOCK_UNLOCKED;

int g_tb_flush_count;
int g_tb_phys_invalidate_count;
int g_tb_alloc_count;

#define code_gen_section __attribute__((aligned(32)))

static void page_flush_tb(void);

#define mmap_lock() \
    do {            \
    } while (0)
#define mmap_unlock() \
    do {              \
    } while (0)

bool tcg_enabled(void) {
    return true;
}

/* Allocate a new translation block. Flush the translation buffer if
   too many translation blocks or too much generated code. */
static TranslationBlock *tb_alloc(target_ulong pc) {
    TranslationBlock *tb;

    if (tcg_ctx->code_gen_ptr + 0x10000 >= tcg_ctx->code_gen_highwater) {
        return NULL;
    }

    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(tb == NULL)) {
        return NULL;
    }

#ifdef CONFIG_SYMBEX
    tb->llvm_function = NULL;
    tb->se_tb = g_sqi.tb.tb_alloc();
#endif

    ++g_tb_alloc_count;

    return tb;
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUArchState *env) {
#ifdef CONFIG_SYMBEX
    g_sqi.tb.flush_tb_cache();
#endif

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        memset(env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof(void *));
    }

    memset(tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof(void *));
    page_flush_tb();

    tcg_region_reset_all();

    g_tb_flush_count++;
    g_tb_alloc_count = 0;
}

#ifdef DEBUG_TB_CHECK

static void tb_invalidate_check(target_ulong address) {
    TranslationBlock *tb;
    int i;
    address &= TARGET_PAGE_MASK;
    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tb_phys_hash[i]; tb != NULL; tb = tb->phys_hash_next) {
            if (!(address + TARGET_PAGE_SIZE <= tb->pc || address >= tb->pc + tb->size)) {
                printf("ERROR invalidate: address=" TARGET_FMT_lx " PC=%08lx size=%04x\n", address, (long) tb->pc,
                       tb->size);
            }
        }
    }
}

/* verify that all the pages have correct rights for code */
static void tb_page_check(void) {
    TranslationBlock *tb;
    int i, flags1, flags2;

    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tb_phys_hash[i]; tb != NULL; tb = tb->phys_hash_next) {
            flags1 = page_get_flags(tb->pc);
            flags2 = page_get_flags(tb->pc + tb->size - 1);
            if ((flags1 & PAGE_WRITE) || (flags2 & PAGE_WRITE)) {
                printf("ERROR page flags: PC=%08lx size=%04x f1=%x f2=%x\n", (long) tb->pc, tb->size, flags1, flags2);
            }
        }
    }
}

#endif

/* invalidate one TB */
static inline void tb_remove(TranslationBlock **ptb, TranslationBlock *tb, int next_offset) {
    TranslationBlock *tb1;
    for (;;) {
        tb1 = *ptb;
        if (tb1 == tb) {
            *ptb = *(TranslationBlock **) ((char *) tb1 + next_offset);
            break;
        }
        ptb = (TranslationBlock **) ((char *) tb1 + next_offset);
    }
}

static inline void tb_page_remove(TranslationBlock **ptb, TranslationBlock *tb) {
    TranslationBlock *tb1;
    unsigned int n1;

    for (;;) {
        tb1 = *ptb;
        n1 = (long) tb1 & 3;
        tb1 = (TranslationBlock *) ((long) tb1 & ~3);
        if (tb1 == tb) {
            *ptb = tb1->page_next[n1];
            break;
        }
        ptb = &tb1->page_next[n1];
    }
}

static inline void invalidate_page_bitmap(PageDesc *p) {
    if (p->code_bitmap) {
        g_free(p->code_bitmap);
        p->code_bitmap = NULL;
    }
    p->code_write_count = 0;
}

void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr) {
    CPUArchState *env;
    PageDesc *p;
    unsigned int h;
    tb_page_addr_t phys_pc;

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_phys_hash_func(phys_pc);
    tb_remove(&tb_phys_hash[h], tb, offsetof(TranslationBlock, phys_hash_next));

    /* remove the TB from the page list */
    if (tb->page_addr[0] != page_addr) {
        p = page_find(tb->page_addr[0] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }
    if (tb->page_addr[1] != -1 && tb->page_addr[1] != page_addr) {
        p = page_find(tb->page_addr[1] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }

    tb_invalidated_flag = 1;

    /* remove the TB from the hash list */
    h = tb_jmp_cache_hash_func(tb->pc);
    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->tb_jmp_cache[h] == tb)
            env->tb_jmp_cache[h] = NULL;
    }

    /* suppress this TB from the two jump lists */
    tb_remove_from_jmp_list(tb, 0);
    tb_remove_from_jmp_list(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb_jmp_unlink(tb);

    g_tb_phys_invalidate_count++;
}

TranslationBlock *tb_gen_code(CPUArchState *env, target_ulong pc, target_ulong cs_base, int flags, int cflags) {
    TranslationBlock *tb;
    tb_page_addr_t phys_pc, phys_page2;
    target_ulong virt_page2;

    phys_pc = get_page_addr_code(env, pc);

again:
    tb = tb_alloc(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(pc);
        /* Don't forget to invalidate previous TB info.  */
        tb_invalidated_flag = 1;
    }

    tb->cflags = 0;
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags | CF_HAS_INTERRUPT_EXIT;

    if (cpu_gen_code(env, tb) < 0) {
        tb_flush(env);
        goto again;
    }

    /* check next page if needed */
    virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
    phys_page2 = -1;

    if ((pc & TARGET_PAGE_MASK) != virt_page2) {
        phys_page2 = get_page_addr_code(env, virt_page2);
    }

    tb_link_page(tb, phys_pc, phys_page2);
    tcg_tb_insert(tb);

    return tb;
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */
static void page_flush_tb_1(int level, void **lp) {
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            pd[i].first_tb = NULL;
            invalidate_page_bitmap(pd + i);
        }
    } else {
        void **pp = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            page_flush_tb_1(level - 1, pp + i);
        }
    }
}

static void page_flush_tb(void) {
    int i;
    for (i = 0; i < V_L1_SIZE; i++) {
        page_flush_tb_1(V_L1_SHIFT / L2_BITS - 1, l1_map + i);
    }
}

static inline void set_bits(uint8_t *tab, int start, int len) {
    int end, mask, end1;

    end = start + len;
    tab += start >> 3;
    mask = 0xff << (start & 7);
    if ((start & ~7) == (end & ~7)) {
        if (start < end) {
            mask &= ~(0xff << (end & 7));
            *tab |= mask;
        }
    } else {
        *tab++ |= mask;
        start = (start + 8) & ~7;
        end1 = end & ~7;
        while (start < end1) {
            *tab++ = 0xff;
            start += 8;
        }
        if (start < end) {
            mask = ~(0xff << (end & 7));
            *tab |= mask;
        }
    }
}

static void build_page_bitmap(PageDesc *p) {
    int n, tb_start, tb_end;
    TranslationBlock *tb;

    p->code_bitmap = g_malloc0(TARGET_PAGE_SIZE / 8);

    tb = p->first_tb;
    while (tb != NULL) {
        n = (long) tb & 3;
        tb = (TranslationBlock *) ((long) tb & ~3);
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->pc & ~TARGET_PAGE_MASK;
            tb_end = tb_start + tb->size;
            if (tb_end > TARGET_PAGE_SIZE)
                tb_end = TARGET_PAGE_SIZE;
        } else {
            tb_start = 0;
            tb_end = ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        set_bits(p->code_bitmap, tb_start, tb_end - tb_start);
        tb = tb->page_next[n];
    }
}

/* invalidate all TBs which intersect with the target physical page
   starting in range [start;end[. NOTE: start and end must refer to
   the same physical page. 'is_cpu_write_access' should be true if called
   from a real cpu write access: the virtual CPU will exit the current
   TB if code is modified inside this TB. */
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end, int is_cpu_write_access) {
    TranslationBlock *tb, *tb_next, *saved_tb;
    CPUArchState *env = cpu_single_env;
    tb_page_addr_t tb_start, tb_end;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    int current_tb_not_found = is_cpu_write_access;
    TranslationBlock *current_tb = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    int current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

    p = page_find(start >> TARGET_PAGE_BITS);
    if (!p)
        return;
    if (!p->code_bitmap && ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD && is_cpu_write_access) {
        /* build code bitmap */
        build_page_bitmap(p);
    }

    /* we remove all the TBs in the range [start, end[ */
    /* XXX: see if in some cases it could be faster to invalidate all the code */
    tb = p->first_tb;
    while (tb != NULL) {
        n = (long) tb & 3;
        tb = (TranslationBlock *) ((long) tb & ~3);
        tb_next = tb->page_next[n];
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
            tb_end = tb_start + tb->size;
        } else {
            tb_start = tb->page_addr[1];
            tb_end = tb_start + ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        if (!(tb_end <= start || tb_start >= end)) {
#ifdef TARGET_HAS_PRECISE_SMC
            if (current_tb_not_found) {
                current_tb_not_found = 0;
                current_tb = NULL;
                if (env->mem_io_pc) {
                    /* now we have a real cpu fault */
                    current_tb = tcg_tb_lookup(env->mem_io_pc);
                }
            }
            if (current_tb == tb && (current_tb->cflags & CF_COUNT_MASK) != 1) {
                current_tb_modified = 1;
                cpu_restore_state(env, env->mem_io_pc);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base, &current_flags);

                // When an instruction modifies itself, advance pc to the next instruction
                // and abort the tb asap.
                int instr_size = tb_get_instruction_size(current_tb, current_tb->cs_base + env->eip);
                assert(instr_size);
                if (current_tb->pc + current_tb->size > env->eip + instr_size) {
                    env->eip += instr_size;
                    tcg_target_force_tb_exit(env->mem_io_pc, (uintptr_t)(current_tb->tc.ptr + current_tb->tc.size));
                }
            }
#endif /* TARGET_HAS_PRECISE_SMC */
            /* we need to do that to handle the case where a signal
               occurs while doing tb_phys_invalidate() */
            saved_tb = NULL;
            if (env) {
                saved_tb = env->current_tb;
                env->current_tb = NULL;
            }
            tb_phys_invalidate(tb, -1);
            if (env) {
                env->current_tb = saved_tb;
#if 0
                if (env->interrupt_request && env->current_tb) {
                    cpu_interrupt(env, env->interrupt_request);
                }
#endif
            }
        }
        tb = tb_next;
    }

    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        invalidate_page_bitmap(p);
        if (is_cpu_write_access) {
#ifdef CONFIG_SYMBEX_MP
            target_ulong iovaddr = g_sqi.mem.read_mem_io_vaddr(1);
            tlb_unprotect_code_phys(env, start, iovaddr);
#else
            tlb_unprotect_code_phys(env, start, env->mem_io_vaddr);
#endif
        }
    }

#ifdef TARGET_HAS_PRECISE_SMC
#ifdef CONFIG_SYMBEX
/* In symbex mode, we don't keep env->mem_io_pc information, so we can't be
   sure whether current tb was invalidated or not. We abort it
   in any case */
/* XXX: is it safe to do ? */
// env->current_tb = NULL;
// cpu_resume_from_signal(env, NULL);
// XXX: check env->mem_io_pc handling!
#endif
#endif
}

/* len must be <= 8 and start must be a multiple of len */
void tb_invalidate_phys_page_fast(tb_page_addr_t start, int len) {
    PageDesc *p;
    int offset, b;
#if 0
    if (1) {
        libcpu_log("modifying code at 0x%x size=%d EIP=%x PC=%08x\n",
                  cpu_single_env->mem_io_vaddr, len,
                  cpu_single_env->eip,
                  cpu_single_env->eip + (long)cpu_single_env->segs[R_CS].base);
    }
#endif
    p = page_find(start >> TARGET_PAGE_BITS);
    if (!p)
        return;
    if (p->code_bitmap) {
        offset = start & ~TARGET_PAGE_MASK;
        b = p->code_bitmap[offset >> 3] >> (offset & 7);
        if (b & ((1 << len) - 1))
            goto do_invalidate;
    } else {
    do_invalidate:
        tb_invalidate_phys_page_range(start, start + len, 1);
    }
}

/* add the tb in the target page and protect it if necessary */
static inline void tb_alloc_page(TranslationBlock *tb, unsigned int n, tb_page_addr_t page_addr) {
    PageDesc *p;
    bool page_already_protected;

    tb->page_addr[n] = page_addr;
    p = page_find_alloc(page_addr >> TARGET_PAGE_BITS, 1);
    tb->page_next[n] = p->first_tb;
    page_already_protected = p->first_tb != NULL;
    p->first_tb = (TranslationBlock *) ((long) tb | n);
    invalidate_page_bitmap(p);

#if defined(TARGET_HAS_SMC) || 1

    /* if some code is already present, then the pages are already
       protected. So we handle the case where only the first TB is
       allocated in a physical page */
    if (!page_already_protected) {
        tlb_protect_code(page_addr);
    }

#endif /* TARGET_HAS_SMC */
}

/* add a new TB and link it to the physical page tables. phys_page2 is
   (-1) to indicate that only one page contains the TB. */
void tb_link_page(TranslationBlock *tb, tb_page_addr_t phys_pc, tb_page_addr_t phys_page2) {
    unsigned int h;
    TranslationBlock **ptb;

    /* Grab the mmap lock to stop another thread invalidating this TB
       before we are done.  */
    mmap_lock();
    /* add in the physical hash table */
    h = tb_phys_hash_func(phys_pc);
    ptb = &tb_phys_hash[h];
    tb->phys_hash_next = *ptb;
    *ptb = tb;

    /* add in the page list */
    tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1)
        tb_alloc_page(tb, 1, phys_page2);
    else
        tb->page_addr[1] = -1;

#ifdef DEBUG_TB_CHECK
    tb_page_check();
#endif
    mmap_unlock();
}

////////////

/* remove @orig from its @n_orig-th jump list */
void tb_remove_from_jmp_list(TranslationBlock *orig, int n_orig) {
    uintptr_t ptr, ptr_locked;
    TranslationBlock *dest;
    TranslationBlock *tb;
    uintptr_t *pprev;
    int n;

    /* mark the LSB of jmp_dest[] so that no further jumps can be inserted */
    ptr = atomic_or_fetch(&orig->jmp_dest[n_orig], 1);
    dest = (TranslationBlock *) (ptr & ~1);
    if (dest == NULL) {
        return;
    }

    spin_lock(&dest->jmp_lock);
    /*
     * While acquiring the lock, the jump might have been removed if the
     * destination TB was invalidated; check again.
     */
    ptr_locked = atomic_read(&orig->jmp_dest[n_orig]);
    if (ptr_locked != ptr) {
        spin_unlock(&dest->jmp_lock);
        /*
         * The only possibility is that the jump was unlinked via
         * tb_jump_unlink(dest). Seeing here another destination would be a bug,
         * because we set the LSB above.
         */
        g_assert(ptr_locked == 1 && dest->cflags & CF_INVALID);
        return;
    }
    /*
     * We first acquired the lock, and since the destination pointer matches,
     * we know for sure that @orig is in the jmp list.
     */
    pprev = &dest->jmp_list_head;
    TB_FOR_EACH_JMP(dest, tb, n) {
        if (tb == orig && n == n_orig) {
            *pprev = tb->jmp_list_next[n];
            /* no need to set orig->jmp_dest[n]; setting the LSB was enough */
            spin_unlock(&dest->jmp_lock);
            return;
        }
        pprev = &tb->jmp_list_next[n];
    }
    g_assert_not_reached();
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
void tb_reset_jump(TranslationBlock *tb, int n) {
    uintptr_t addr = (uintptr_t)(tb->tc.ptr + tb->jmp_reset_offset[n]);
    tb_set_jmp_target(tb, n, addr);
}

/* remove any jumps to the TB */
void tb_jmp_unlink(TranslationBlock *dest) {
    TranslationBlock *tb;
    int n;

    spin_lock(&dest->jmp_lock);

    TB_FOR_EACH_JMP(dest, tb, n) {
        tb_reset_jump(tb, n);
        atomic_and(&tb->jmp_dest[n], (uintptr_t) NULL | 1);
        /* No need to clear the list entry; setting the dest ptr is enough */
    }
    dest->jmp_list_head = (uintptr_t) NULL;

    spin_unlock(&dest->jmp_lock);
}

void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr) {
    if (TCG_TARGET_HAS_direct_jump) {
        uintptr_t offset = tb->jmp_target_arg[n];
        uintptr_t tc_ptr = (uintptr_t) tb->tc.ptr;
        tb_target_set_jmp_target(tc_ptr, tc_ptr + offset, addr);
    } else {
        tb->jmp_target_arg[n] = addr;
    }
}

void tb_add_jump(TranslationBlock *tb, int n, TranslationBlock *tb_next) {
    uintptr_t old;

    assert(n < ARRAY_SIZE(tb->jmp_list_next));
    spin_lock(&tb_next->jmp_lock);

    /* make sure the destination TB is valid */
    if (tb_next->cflags & CF_INVALID) {
        goto out_unlock_next;
    }
    /* Atomically claim the jump destination slot only if it was NULL */
    old = atomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t) NULL, (uintptr_t) tb_next);
    if (old) {
        goto out_unlock_next;
    }

    /* patch the native jump address */
    tb_set_jmp_target(tb, n, (uintptr_t) tb_next->tc.ptr);

    /* add in TB jmp list */
    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t) tb | n;

    spin_unlock(&tb_next->jmp_lock);

    libcpu_log_mask(CPU_LOG_EXEC, "Linking TBs %p [" TARGET_FMT_lx "] index %d -> %p [" TARGET_FMT_lx "]\n", tb->tc.ptr,
                    tb->pc, n, tb_next->tc.ptr, tb_next->pc);
    return;

out_unlock_next:
    spin_unlock(&tb_next->jmp_lock);
    return;
}
