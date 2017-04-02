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
#include <glib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <tcg/tcg.h>
#include "cpu.h"
#include "osdep.h"
#include "qemu-common.h"

#include "exec-phystb.h"
#include "exec.h"

#ifdef CONFIG_SYMBEX
#include <cpu-all.h>
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#endif

#include "exec-tb.h"

TranslationBlock *g_tbs;
int g_nb_tbs;

TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];

/* any access to the tbs or the page table must use this lock */
spinlock_t tb_lock = SPIN_LOCK_UNLOCKED;

int g_tb_flush_count;
int g_tb_phys_invalidate_count;

int code_gen_max_blocks;

#define code_gen_section __attribute__((aligned(32)))

uint8_t code_gen_prologue[1024] code_gen_section;
uint8_t *code_gen_buffer;
unsigned long code_gen_buffer_size;
/* threshold to flush the translated code buffer */
unsigned long g_code_gen_buffer_max_size;
uint8_t *g_code_gen_ptr;

#ifdef CONFIG_SYMBEX
static tb_precise_pc_t *code_gen_precise_excp_buffer;
static tb_precise_pc_t *code_gen_precise_excp_ptr;
static unsigned long code_gen_precise_excp_count;
static unsigned long code_gen_precise_excp_max_count;
#endif

static void page_flush_tb(void);

unsigned long qemu_real_host_page_size;
unsigned long qemu_host_page_size;
unsigned long qemu_host_page_mask;

#define DEFAULT_CODE_GEN_BUFFER_SIZE (32 * 1024 * 1024)

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE] __attribute__((aligned(CODE_GEN_ALIGN)));
#endif

#ifdef _WIN32
static void map_exec(void *addr, long size) {
    DWORD old_protect;
    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old_protect);
}
#else
static void map_exec(void *addr, long size) {
    unsigned long start, end, page_size;

    page_size = getpagesize();
    start = (unsigned long) addr;
    start &= ~(page_size - 1);

    end = (unsigned long) addr + size;
    end += page_size - 1;
    end &= ~(page_size - 1);

    mprotect((void *) start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC);
}
#endif

#define mmap_lock() \
    do {            \
    } while (0)
#define mmap_unlock() \
    do {              \
    } while (0)

#ifdef CONFIG_SYMBEX
static void code_gen_init_precise_excep(void) {
    /**
     * Have a 4KB overflow buffer, a TB is guaranteed not to have
     * more than 4K guest instructions.
     */

    if (code_gen_precise_excp_count == 0) {
        code_gen_precise_excp_count = code_gen_max_blocks;
        code_gen_precise_excp_max_count = code_gen_precise_excp_count - 0x1000;
        code_gen_precise_excp_buffer = g_malloc(code_gen_precise_excp_count * sizeof(tb_precise_pc_t));
        code_gen_precise_excp_ptr = code_gen_precise_excp_buffer;
    } else {
        // Resize the buffer. Must be done after the TB cache is flushed.
        // g_sqi.log.debug("Resizing precise exception buffer from %d to %d entries\n", code_gen_precise_excp_count,
        // code_gen_precise_excp_count * 2);
        code_gen_precise_excp_count *= 2;
        code_gen_precise_excp_max_count = code_gen_precise_excp_count - 0x1000;
        code_gen_precise_excp_buffer =
            g_realloc(code_gen_precise_excp_buffer, code_gen_precise_excp_count * sizeof(tb_precise_pc_t));
        code_gen_precise_excp_ptr = code_gen_precise_excp_buffer;
    }
}

static bool code_gen_precise_excep_flush_needed(void) {
    return (code_gen_precise_excp_ptr - code_gen_precise_excp_buffer) >= code_gen_precise_excp_max_count;
}

#endif

static void code_gen_alloc(unsigned long tb_size) {
#ifdef USE_STATIC_CODE_GEN_BUFFER
    code_gen_buffer = static_code_gen_buffer;
    code_gen_buffer_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
    map_exec(code_gen_buffer, code_gen_buffer_size);
#else
    code_gen_buffer_size = tb_size;
    if (code_gen_buffer_size == 0) {
        /* XXX: needs adjustments */
        code_gen_buffer_size = (unsigned long) (ram_size / 4);
    }
    if (code_gen_buffer_size < MIN_CODE_GEN_BUFFER_SIZE)
        code_gen_buffer_size = MIN_CODE_GEN_BUFFER_SIZE;
/* The code gen buffer location may have constraints depending on
   the host cpu and OS */
#if defined(__linux__)
    {
        int flags;
        void *start = NULL;

        flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(__x86_64__)
        flags |= MAP_32BIT;
        /* Cannot map more than that */
        if (code_gen_buffer_size > (800 * 1024 * 1024))
            code_gen_buffer_size = (800 * 1024 * 1024);
#endif
        code_gen_buffer = mmap(start, code_gen_buffer_size, PROT_WRITE | PROT_READ | PROT_EXEC, flags, -1, 0);
        if (code_gen_buffer == MAP_FAILED) {
            fprintf(stderr, "Could not allocate dynamic translator buffer\n");
            exit(1);
        }
    }
#else
    code_gen_buffer = g_malloc(code_gen_buffer_size);
    map_exec(code_gen_buffer, code_gen_buffer_size);
#endif
#endif /* !USE_STATIC_CODE_GEN_BUFFER */
    map_exec(code_gen_prologue, sizeof(code_gen_prologue));
    g_code_gen_buffer_max_size = code_gen_buffer_size - (TCG_MAX_OP_SIZE * OPC_BUF_SIZE);
    code_gen_max_blocks = code_gen_buffer_size / CODE_GEN_AVG_BLOCK_SIZE;
    g_tbs = g_malloc(code_gen_max_blocks * sizeof(TranslationBlock));

#ifdef CONFIG_SYMBEX
    code_gen_init_precise_excep();

    cpu_gen_init_opc();
#endif
}

static void page_init(void) {
/* NOTE: we can always suppose that qemu_host_page_size >=
   TARGET_PAGE_SIZE */
#ifdef _WIN32
    {
        SYSTEM_INFO system_info;

        GetSystemInfo(&system_info);
        qemu_real_host_page_size = system_info.dwPageSize;
    }
#else
    qemu_real_host_page_size = getpagesize();
#endif
    if (qemu_host_page_size == 0)
        qemu_host_page_size = qemu_real_host_page_size;
    if (qemu_host_page_size < TARGET_PAGE_SIZE)
        qemu_host_page_size = TARGET_PAGE_SIZE;
    qemu_host_page_mask = ~(qemu_host_page_size - 1);
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(unsigned long tb_size) {
    cpu_gen_init();
    code_gen_alloc(tb_size);
    g_code_gen_ptr = code_gen_buffer;
#ifdef CONFIG_SYMBEX
    code_gen_precise_excp_ptr = code_gen_precise_excp_buffer;
#endif
    tcg_register_jit(code_gen_buffer, code_gen_buffer_size);
    page_init();

    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(&tcg_ctx);
}

bool tcg_enabled(void) {
    return code_gen_buffer != NULL;
}

/* Allocate a new translation block. Flush the translation buffer if
   too many translation blocks or too much generated code. */
static TranslationBlock *tb_alloc(target_ulong pc) {
    TranslationBlock *tb;

#ifdef CONFIG_SYMBEX
    if (g_nb_tbs >= code_gen_max_blocks || (g_code_gen_ptr - code_gen_buffer) >= g_code_gen_buffer_max_size ||
        code_gen_precise_excep_flush_needed() || cpu_gen_flush_needed())
#else
    if (g_nb_tbs >= code_gen_max_blocks || (g_code_gen_ptr - code_gen_buffer) >= g_code_gen_buffer_max_size)
#endif

    {
        return NULL;
    }
    tb = &g_tbs[g_nb_tbs++];
    tb->pc = pc;
    tb->cflags = 0;

#ifdef CONFIG_SYMBEX
    tb->llvm_function = NULL;
    tb->se_tb = NULL;
    g_sqi.tb.tb_alloc(tb);
#endif

    return tb;
}

void tb_free(TranslationBlock *tb) {
    /* In practice this is mostly used for single use temporary TB
       Ignore the hard cases and just back up if this TB happens to
       be the last one generated.  */
    if (g_nb_tbs > 0 && tb == &g_tbs[g_nb_tbs - 1]) {
        g_code_gen_ptr = tb->tc_ptr;

#if defined(CONFIG_SYMBEX)
        code_gen_precise_excp_ptr = tb->precise_pcs;
        g_sqi.tb.tb_free(tb);
#endif
        g_nb_tbs--;
    }
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUArchState *env1) {
#ifdef CONFIG_SYMBEX
    g_sqi.tb.flush_tb_cache();
#endif

    CPUArchState *env;
#if defined(DEBUG_FLUSH)
    printf("qemu: flush code_size=%ld g_nb_tbs=%d avg_tb_size=%ld\n",
           (unsigned long) (g_code_gen_ptr - code_gen_buffer), g_nb_tbs,
           g_nb_tbs > 0 ? ((unsigned long) (g_code_gen_ptr - code_gen_buffer)) / g_nb_tbs : 0);
#endif
    if ((unsigned long) (g_code_gen_ptr - code_gen_buffer) > code_gen_buffer_size)
        cpu_abort(env1, "Internal error: code buffer overflow\n");

#ifdef CONFIG_SYMBEX
    if ((code_gen_precise_excp_ptr - code_gen_precise_excp_buffer) > code_gen_precise_excp_count) {
        cpu_abort(env1, "Internal error: exception buffer overflow\n");
    }
#endif

#if defined(CONFIG_SYMBEX)
    int i1;
    for (i1 = 0; i1 < g_nb_tbs; ++i1)
        g_sqi.tb.tb_free(&g_tbs[i1]);
#endif

    g_nb_tbs = 0;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        memset(env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof(void *));
    }

    memset(tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof(void *));
    page_flush_tb();

    g_code_gen_ptr = code_gen_buffer;

#ifdef CONFIG_SYMBEX
    cpu_gen_flush();

    if (code_gen_precise_excep_flush_needed()) {
        code_gen_init_precise_excep();
    }

    code_gen_precise_excp_ptr = code_gen_precise_excp_buffer;
#endif
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    g_tb_flush_count++;
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

static inline void tb_jmp_remove(TranslationBlock *tb, int n) {
    TranslationBlock *tb1, **ptb;
    unsigned int n1;

    ptb = &tb->jmp_next[n];
    tb1 = *ptb;
    if (tb1) {
        /* find tb(n) in circular list */
        for (;;) {
            tb1 = *ptb;
            n1 = (long) tb1 & 3;
            tb1 = (TranslationBlock *) ((long) tb1 & ~3);
            if (n1 == n && tb1 == tb)
                break;
            if (n1 == 2) {
                ptb = &tb1->jmp_first;
            } else {
                ptb = &tb1->jmp_next[n1];
            }
        }
        /* now we can suppress tb(n) from the list */
        *ptb = tb->jmp_next[n];

        tb->jmp_next[n] = NULL;
#ifdef CONFIG_SYMBEX
        tb->se_tb_next[n] = NULL;
#endif
    }
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
static inline void tb_reset_jump(TranslationBlock *tb, int n) {
    tb_set_jmp_target(tb, n, (unsigned long) (tb->tc_ptr + tb->tb_next_offset[n]));

#ifdef CONFIG_SYMBEX
    tb->se_tb_next[n] = NULL;
#endif
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
    unsigned int h, n1;
    tb_page_addr_t phys_pc;
    TranslationBlock *tb1, *tb2;

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
    tb_jmp_remove(tb, 0);
    tb_jmp_remove(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb1 = tb->jmp_first;
    for (;;) {
        n1 = (long) tb1 & 3;
        if (n1 == 2)
            break;
        tb1 = (TranslationBlock *) ((long) tb1 & ~3);
        tb2 = tb1->jmp_next[n1];
        tb_reset_jump(tb1, n1);
        tb1->jmp_next[n1] = NULL;
        tb1 = tb2;
    }
    tb->jmp_first = (TranslationBlock *) ((long) tb | 2); /* fail safe */

    g_tb_phys_invalidate_count++;
}

TranslationBlock *tb_gen_code(CPUArchState *env, target_ulong pc, target_ulong cs_base, int flags, int cflags) {
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    tb_page_addr_t phys_pc, phys_page2;
    target_ulong virt_page2;
    int code_gen_size;

    phys_pc = get_page_addr_code(env, pc);
    tb = tb_alloc(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(pc);
        /* Don't forget to invalidate previous TB info.  */
        tb_invalidated_flag = 1;
    }

#ifdef CONFIG_SYMBEX
    tb->originalTb = NULL;
    tb->precise_entries = 0;
    tb->precise_pcs = code_gen_precise_excp_ptr;
    assert(code_gen_precise_excp_ptr < code_gen_precise_excp_buffer + code_gen_precise_excp_max_count);
#endif

    tc_ptr = g_code_gen_ptr;
    tb->tc_ptr = tc_ptr;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;

    cpu_gen_code(env, tb, &code_gen_size);
    tb->tc_size = code_gen_size;
    g_code_gen_ptr =
        (void *) (((unsigned long) g_code_gen_ptr + code_gen_size + CODE_GEN_ALIGN - 1) & ~(CODE_GEN_ALIGN - 1));

#ifdef CONFIG_SYMBEX
// Do not store precise TB info if the block is not instrumented
#if !defined(SE_ENABLE_RETRANSLATION)
    code_gen_precise_excp_ptr += tb->icount;
    ++code_gen_precise_excp_ptr;
    assert(code_gen_precise_excp_ptr < code_gen_precise_excp_buffer + code_gen_precise_excp_count);
#else
    if (tb->instrumented) {
        code_gen_precise_excp_ptr += tb->icount;
        ++code_gen_precise_excp_ptr;
        assert(code_gen_precise_excp_ptr < code_gen_precise_excp_buffer + code_gen_precise_excp_count);
    } else {
        tb->precise_entries = -1;
        tb->precise_pcs = NULL;
    }
#endif
#endif

    /* check next page if needed */
    virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
    phys_page2 = -1;
    if ((pc & TARGET_PAGE_MASK) != virt_page2) {
        phys_page2 = get_page_addr_code(env, virt_page2);
    }
    tb_link_page(tb, phys_pc, phys_page2);

    return tb;
}

#ifdef CONFIG_SYMBEX
void se_setup_precise_pc(TranslationBlock *tb) {
    tb->tc_ptr = g_code_gen_ptr;
    tb->precise_entries = 0;
    tb->precise_pcs = code_gen_precise_excp_ptr;
    assert(code_gen_precise_excp_ptr < code_gen_precise_excp_buffer + code_gen_precise_excp_max_count);
}

void se_tb_gen_llvm(CPUArchState *env, TranslationBlock *tb) {
    /* Operate on a copy to avoid clobbering the original one */
    TranslationBlock llvm_tb = *tb;
    int code_gen_size;

    llvm_tb.originalTb = tb;
    se_setup_precise_pc(&llvm_tb);
    cpu_gen_code(env, &llvm_tb, &code_gen_size);
    cpu_gen_llvm(env, &llvm_tb);
    tb->llvm_function = llvm_tb.llvm_function;
    g_sqi.tb.set_tb_function(tb);
}

#endif

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
                    current_tb = tb_find_pc(env->mem_io_pc);
                }
            }
            if (current_tb == tb && (current_tb->cflags & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                its execution. We could be more precise by checking
                that the modification is after the current PC, but it
                would require a specialized function to partially
                restore the CPU state */

                current_tb_modified = 1;
                cpu_restore_state(current_tb, env, env->mem_io_pc);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base, &current_flags);

                if (restore_state_to_next_pc(env, current_tb)) {
                    // XXX: could also be +2
                    tcg_target_force_tb_exit(env->mem_io_pc + 1, (uintptr_t)(current_tb->tc_ptr + current_tb->tc_size));
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
#ifdef CONFIG_SYMBEX
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

    tb->jmp_first = (TranslationBlock *) ((long) tb | 2);
    tb->jmp_next[0] = NULL;
    tb->jmp_next[1] = NULL;

    /* init original jump addresses */
    if (tb->tb_next_offset[0] != 0xffff)
        tb_reset_jump(tb, 0);
    if (tb->tb_next_offset[1] != 0xffff)
        tb_reset_jump(tb, 1);

#ifdef DEBUG_TB_CHECK
    tb_page_check();
#endif
    mmap_unlock();
}

/* find the TB 'tb' such that tb[0].tc_ptr <= tc_ptr <
   tb[1].tc_ptr. Return NULL if not found */
TranslationBlock *tb_find_pc(uintptr_t tc_ptr) {
    int m_min, m_max, m;
    unsigned long v;
    TranslationBlock *tb;

    if (g_nb_tbs <= 0)
        return NULL;

    if (tc_ptr < (unsigned long) code_gen_buffer || tc_ptr >= (unsigned long) g_code_gen_ptr)
        return NULL;
    /* binary search (cf Knuth) */
    m_min = 0;
    m_max = g_nb_tbs - 1;
    while (m_min <= m_max) {
        m = (m_min + m_max) >> 1;
        tb = &g_tbs[m];
        v = (unsigned long) tb->tc_ptr;
        if (v == tc_ptr)
            return tb;
        else if (tc_ptr < v) {
            m_max = m - 1;
        } else {
            m_min = m + 1;
        }
    }
    return &g_tbs[m_max];
}

static void tb_reset_jump_recursive(TranslationBlock *tb);

static inline void tb_reset_jump_recursive2(TranslationBlock *tb, int n) {
    TranslationBlock *tb1, *tb_next, **ptb;
    unsigned int n1;

    tb1 = tb->jmp_next[n];
    if (tb1 != NULL) {
        /* find head of list */
        for (;;) {
            n1 = (long) tb1 & 3;
            tb1 = (TranslationBlock *) ((long) tb1 & ~3);
            if (n1 == 2)
                break;
            tb1 = tb1->jmp_next[n1];
        }
        /* we are now sure now that tb jumps to tb1 */
        tb_next = tb1;

        /* remove tb from the jmp_first list */
        ptb = &tb_next->jmp_first;
        for (;;) {
            tb1 = *ptb;
            n1 = (long) tb1 & 3;
            tb1 = (TranslationBlock *) ((long) tb1 & ~3);
            if (n1 == n && tb1 == tb)
                break;
            ptb = &tb1->jmp_next[n1];
        }
        *ptb = tb->jmp_next[n];
        tb->jmp_next[n] = NULL;

        /* suppress the jump to next tb in generated code */
        tb_reset_jump(tb, n);

        /* suppress jumps in the tb on which we could have jumped */
        tb_reset_jump_recursive(tb_next);
    }
}

static void tb_reset_jump_recursive(TranslationBlock *tb) {
    tb_reset_jump_recursive2(tb, 0);
    tb_reset_jump_recursive2(tb, 1);
}

void cpu_unlink_tb(CPUArchState *env) {
    TranslationBlock *tb;

    /**
     * Unlinking can happen from different threads and signals,
     * must make it thread safe.
     */
    tb = env->current_tb;

    /* if the cpu is currently executing code, we must unlink it and
       all the potentially executing TB */
    if (tb) {
        env->current_tb = NULL;
        tb_reset_jump_recursive(tb);
        ++g_cpu_stats.tb_unlinks;
    }
}
