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
#include <tcg/tb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
typedef ram_addr_t tb_page_addr_t;

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
int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc);

void tb_free(TranslationBlock *tb);
void tb_link_page(TranslationBlock *tb, tb_page_addr_t phys_pc, tb_page_addr_t phys_page2);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCPU_TB_H__ */
