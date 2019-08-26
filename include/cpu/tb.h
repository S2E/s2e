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

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef CONFIG_SYMBEX

///
/// \brief tb_get_instruction_size returns the size of the guest machine
/// instruction starting at the given address and belonging to the given
/// translation block. Useful for variable-length instruction sets.
///
/// \param tb the translation block in which the instruction is located
/// \param addr the absolute virtual address at which the instruction starts
/// \returns the size of the instruction in bytes, or 0 if no instruction
/// starting at the given address is found in the translation block
///
static inline uint8_t tb_get_instruction_size(TranslationBlock *tb, uint64_t addr) {
    int i;

    for (i = 0; i < tb->precise_entries; i++) {
        if (tb->pc + tb->precise_pcs[i].guest_pc_increment == addr) {
            return tb->precise_pcs[i].guest_inst_size;
        }
    }

    return 0;
}
#endif /* CONFIG_SYMBEX */

void tb_free(TranslationBlock *tb);
void tb_link_page(TranslationBlock *tb, tb_page_addr_t phys_pc, tb_page_addr_t phys_page2);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCPU_TB_H__ */
