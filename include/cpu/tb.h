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

#ifndef __LIBCPU_TB_H__

#define __LIBCPU_TB_H__

#include <cpu/se_libcpu_config.h>
#include <cpu/types.h>
#include <tcg/cpu.h>

enum ETranslationBlockType {
    TB_DEFAULT = 0,
    TB_JMP,
    TB_JMP_IND,
    TB_COND_JMP,
    TB_COND_JMP_IND,
    TB_CALL,
    TB_CALL_IND,
    TB_REP,
    TB_RET,
    TB_IRET,
    TB_EXCP,
    TB_SYSENTER
};

#ifdef CONFIG_SYMBEX
enum JumpType { JT_RET, JT_LRET };
#endif

#if defined(_ARCH_PPC) || defined(__x86_64__) || defined(__arm__) || defined(__i386__)
#define USE_DIRECT_JUMP
#elif defined(CONFIG_TCG_INTERPRETER)
#define USE_DIRECT_JUMP
#endif

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
typedef ram_addr_t tb_page_addr_t;

struct TranslationBlock {
    target_ulong pc;      /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint64_t flags;       /* flags defining in which context the code was generated */
    uint16_t size;        /* size of target code for this block (1 <=
                             size <= TARGET_PAGE_SIZE) */
    uint16_t cflags;      /* compile flags */
#define CF_COUNT_MASK 0x7fff
#define CF_LAST_IO 0x8000 /* Last insn may be an IO access.  */

    uint8_t *tc_ptr;  /* pointer to the translated code */
    unsigned tc_size; /* size of the translated code */

    /* next matching tb for physical address. */
    struct TranslationBlock *phys_hash_next;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    /* the following data are used to directly call another TB from
       the code of this one. */
    uint16_t tb_next_offset[2]; /* offset of original jump target */
#ifdef USE_DIRECT_JUMP
    uint16_t tb_jmp_offset[2]; /* offset of jump instruction */
#else
    uintptr_t tb_next[2]; /* address of jump generated code */
#endif
    /* list of TBs jumping to this one. This is a circular list using
       the two least significant bits of the pointers to tell what is
       the next pointer: 0 = jmp_next[0], 1 = jmp_next[1], 2 =
       jmp_first */
    struct TranslationBlock *jmp_next[2];
    struct TranslationBlock *jmp_first;
    uint32_t icount;

#ifdef CONFIG_SYMBEX
    /* pointer to LLVM translated code */
    void *llvm_function;
#endif

#ifdef CONFIG_SYMBEX
    uint64_t reg_rmask;           /* Registers that TB reads (before overwritting) */
    uint64_t reg_wmask;           /* Registers that TB writes */
    uint64_t helper_accesses_mem; /* True if contains helpers that access mem */

    enum ETranslationBlockType se_tb_type;
    uint64_t se_tb_call_eip;
    void *se_tb;
    struct TranslationBlock *se_tb_next[2];
    uint64_t pcOfLastInstr; /* XXX: hack for call instructions */

    tb_precise_pc_t *precise_pcs;
    int precise_entries;

    /* Indicates whether there are execution handlers attached */
    int instrumented;

    /* Points to the original TB when retranslating to LLVM */
    struct TranslationBlock *originalTb;
#ifdef TCG_KEEP_OPC
    uint16_t *gen_opc_buf;
    void *gen_opparam_buf; // TCGArg*
    unsigned gen_opc_count;

    /* Store minimum TCG state to later reconstruct LLVM bitcode */
    void *tcg_temps;
    int tcg_nb_globals;
    int tcg_nb_temps;
#endif

#ifdef STATIC_TRANSLATOR
    /* pc after which to stop the translation */
    target_ulong last_pc;
#endif
#endif
};

typedef struct TranslationBlock TranslationBlock;

#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/* Only the bottom TB_JMP_PAGE_BITS of the jump cache hash bits vary for
   addresses on the same page.  The top bits are the same.  This allows
   TLB invalidation to quickly clear a subset of the hash table.  */
#define TB_JMP_PAGE_BITS (TB_JMP_CACHE_BITS / 2)
#define TB_JMP_PAGE_SIZE (1 << TB_JMP_PAGE_BITS)
#define TB_JMP_ADDR_MASK (TB_JMP_PAGE_SIZE - 1)
#define TB_JMP_PAGE_MASK (TB_JMP_CACHE_SIZE - TB_JMP_PAGE_SIZE)

#if defined(USE_DIRECT_JUMP)

#if defined(CONFIG_TCG_INTERPRETER)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr) {
    /* patch the branch destination */
    uint32_t val = addr - (jmp_addr + 4);
    __atomic_store_n((uint32_t *) jmp_addr, &val, __ATOMIC_SEQ_CST);
    /* no need to flush icache explicitly */
}
#elif defined(_ARCH_PPC)
void ppc_tb_set_jmp_target(unsigned long jmp_addr, unsigned long addr);
#define tb_set_jmp_target1 ppc_tb_set_jmp_target
#elif defined(__i386__) || defined(__x86_64__)

///
/// \brief tb_set_jmp_target1 sets the jump destination of the translation
/// block to the specificed address.
///
/// Translated blocks contain a jump of the form "jmp offset"
/// in order to implement TB chaining. Overwriting the jump offset
/// must be done atomically because the translated code and the overwrite
/// often run in different threads. The write is usually unaligned,
/// which means that without a lock, the instruction decoder could see
/// a partially written target. Note that locking was not required
/// in vanilla QEMU, because writes were done from a signal running
/// in the CPU thread, eliminating race conditions.
///
/// \param jmp_addr the address of the jump offset
/// \param addr the new target of the jump
///
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr) {
    /* patch the branch destination */
    uint32_t val = addr - (jmp_addr + 4);
    __atomic_store_n((uint32_t *) jmp_addr, val, __ATOMIC_SEQ_CST);
    /* no need to flush icache explicitly */
}
#elif defined(__arm__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr) {
#if !LIBCPU_GNUC_PREREQ(4, 1)
    register unsigned long _beg __asm("a1");
    register unsigned long _end __asm("a2");
    register unsigned long _flg __asm("a3");
#endif

    /* we could use a ldr pc, [pc, #-4] kind of branch and avoid the flush */
    *(uint32_t *) jmp_addr = (*(uint32_t *) jmp_addr & ~0xffffff) | (((addr - (jmp_addr + 8)) >> 2) & 0xffffff);

#if LIBCPU_GNUC_PREREQ(4, 1)
    __builtin___clear_cache((char *) jmp_addr, (char *) jmp_addr + 4);
#else
    /* flush icache */
    _beg = jmp_addr;
    _end = jmp_addr + 4;
    _flg = 0;
    __asm __volatile__("swi 0x9f0002" : : "r"(_beg), "r"(_end), "r"(_flg));
#endif
}
#else
#error tb_set_jmp_target1 is missing
#endif

static inline void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr) {
    uint16_t offset = tb->tb_jmp_offset[n];
    tb_set_jmp_target1((uintptr_t)(tb->tc_ptr + offset), addr);
}

#else

/* set the jump target */
static inline void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr) {
    tb->tb_next[n] = addr;
}

#endif

static inline void tb_add_jump(TranslationBlock *tb, int n, TranslationBlock *tb_next) {
    /* NOTE: this test is only needed for thread safety */
    if (!tb->jmp_next[n]) {
        /* patch the native jump address */
        tb_set_jmp_target(tb, n, (uintptr_t) tb_next->tc_ptr);

        /* add in TB jmp circular list */
        tb->jmp_next[n] = tb_next->jmp_first;
        tb_next->jmp_first = (TranslationBlock *) ((uintptr_t)(tb) | (n));
#ifdef CONFIG_SYMBEX
        tb->se_tb_next[n] = tb_next;
#endif
    }
}

#endif
