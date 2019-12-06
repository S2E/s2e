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

#ifndef _TCG_TB_H_

#define _TCG_TB_H_

#include <inttypes.h>
#include <tcg/exec.h>
#include <tcg/utils/atomic.h>

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
    TB_SYSENTER,
    TB_INTERRUPT
};

#ifdef CONFIG_SYMBEX
enum JumpType { JT_RET, JT_LRET };
#endif

// XXX
typedef uintptr_t tb_page_addr_t;

#if defined(_ARCH_PPC) || defined(__x86_64__) || defined(__arm__) || defined(__i386__)
#define USE_DIRECT_JUMP
#elif defined(CONFIG_TCG_INTERPRETER)
#define USE_DIRECT_JUMP
#endif

// XXX
typedef int spinlock_t;

struct TranslationBlock {
    target_ulong pc;      /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint64_t flags;       /* flags defining in which context the code was generated */
    uint16_t size;        /* size of target code for this block (1 <=
                             size <= TARGET_PAGE_SIZE) */

#define CF_COUNT_MASK 0x00007fff
#define CF_NOCACHE 0x00010000            /* To be freed after execution */
#define CF_HAS_INTERRUPT_EXIT 0x00020000 /* The TB has a prologue to handle quick CPU loop exit */
#define CF_INVALID 0x00040000            /* TB is stale. Set with @jmp_lock held */
#define CF_PARALLEL 0x00080000           /* Generate code for a parallel context */

    uint32_t cflags; /* compile flags */

    // uint8_t *tc_ptr;  /* pointer to the translated code */
    // unsigned tc_size; /* size of the translated code */
    struct tb_tc tc;

    /* next matching tb for physical address. */
    struct TranslationBlock *phys_hash_next;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    /* jmp_lock placed here to fill a 4-byte hole. Its documentation is below */
    spinlock_t jmp_lock;

    /* The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
    uint16_t jmp_reset_offset[2];          /* offset of original jump target */
#define TB_JMP_RESET_OFFSET_INVALID 0xffff /* indicates no jump generated */
    uintptr_t jmp_target_arg[2];           /* target address or offset */

    /*
     * Each TB has a NULL-terminated list (jmp_list_head) of incoming jumps.
     * Each TB can have two outgoing jumps, and therefore can participate
     * in two lists. The list entries are kept in jmp_list_next[2]. The least
     * significant bit (LSB) of the pointers in these lists is used to encode
     * which of the two list entries is to be used in the pointed TB.
     *
     * List traversals are protected by jmp_lock. The destination TB of each
     * outgoing jump is kept in jmp_dest[] so that the appropriate jmp_lock
     * can be acquired from any origin TB.
     *
     * jmp_dest[] are tagged pointers as well. The LSB is set when the TB is
     * being invalidated, so that no further outgoing jumps from it can be set.
     *
     * jmp_lock also protects the CF_INVALID cflag; a jump must not be chained
     * to a destination TB that has CF_INVALID set.
     */
    uintptr_t jmp_list_head;
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_dest[2];

    uint32_t icount;

#ifdef CONFIG_SYMBEX
    /* pointer to LLVM translated code */
    void *llvm_function;
#endif

#ifdef CONFIG_SYMBEX
    enum ETranslationBlockType se_tb_type;
    uint64_t se_tb_call_eip;
    void *se_tb;
    uint64_t pcOfLastInstr; /* XXX: hack for call instructions */

    /* Indicates whether there are execution handlers attached */
    int instrumented;

#ifdef STATIC_TRANSLATOR
    /* pc after which to stop the translation */
    target_ulong last_pc;
#endif
#endif
};

typedef struct TranslationBlock TranslationBlock;

/* Hide the atomic_read to make code a little easier on the eyes */
static inline uint32_t tb_cflags(const TranslationBlock *tb) {
    return atomic_read(&tb->cflags);
}

#ifdef __cplusplus
}
#endif

#endif
