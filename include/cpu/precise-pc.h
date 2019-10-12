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

#ifndef _LIBCPU_PRECISE_PC_

#define _LIBCPU_PRECISE_PC_

#include <inttypes.h>
#include <stdbool.h>

#include <cpu/config.h>
#include <cpu/exec.h>
#include <cpu/types.h>

struct TCGContext;
struct TranslationBlock;

typedef struct TCGContext TCGContext;
typedef struct TranslationBlock TranslationBlock;

bool cpu_restore_state(CPUArchState *env, uintptr_t host_pc);
int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc);
int encode_search(TCGContext *tcg_ctx, TranslationBlock *tb, uint8_t *block);

#endif
