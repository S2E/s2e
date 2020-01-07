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

#ifndef __EXEC_TB_H__

#define __EXEC_TB_H__

#include <cpu/tb.h>
#include <inttypes.h>

struct TranslationBlock;

void tb_invalidate_phys_page_fast(tb_page_addr_t start, int len);

/* list iterators for lists of tagged pointers in TranslationBlock */
#define TB_FOR_EACH_TAGGED(head, tb, n, field)                                                               \
    for (n = (head) &1, tb = (TranslationBlock *) ((head) & ~1); tb; tb = (TranslationBlock *) tb->field[n], \
        n = (uintptr_t) tb & 1, tb = (TranslationBlock *) ((uintptr_t) tb & ~1))

#define PAGE_FOR_EACH_TB(pagedesc, tb, n) TB_FOR_EACH_TAGGED((pagedesc)->first_tb, tb, n, page_next)

#define TB_FOR_EACH_JMP(head_tb, tb, n) TB_FOR_EACH_TAGGED((head_tb)->jmp_list_head, tb, n, jmp_list_next)

void tb_remove_from_jmp_list(TranslationBlock *orig, int n_orig);
void tb_reset_jump(TranslationBlock *tb, int n);
void tb_jmp_unlink(TranslationBlock *dest);
void tb_add_jump(TranslationBlock *tb, int n, TranslationBlock *tb_next);
void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr);

#endif
