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

struct TranslationBlock;

extern TranslationBlock *g_tbs;
extern int g_nb_tbs;
extern int code_gen_max_blocks;
extern uint8_t *g_code_gen_ptr;
extern unsigned long g_code_gen_buffer_max_size;
extern int g_tb_phys_invalidate_count;
extern int g_tb_flush_count;

void cpu_unlink_tb(CPUArchState *env);
void tb_invalidate_phys_page_fast(tb_page_addr_t start, int len);

#endif
