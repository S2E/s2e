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

/// @file
/// Types that tcg/exec/translation-block.h needs and upstream's TCG does not
/// provide: the S2E classification of translation blocks, and ram_addr_t, which
/// upstream defines in system/ram_addr.h. libtcg cannot include libcpu, so
/// libcpu takes ram_addr_t from here.

#ifndef S2E_TCG_TB_S2E_H
#define S2E_TCG_TB_S2E_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t ram_addr_t;
#define RAM_ADDR_MAX UINTPTR_MAX
#define RAM_ADDR_FMT "%" PRIxPTR

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

#ifdef __cplusplus
}
#endif

#endif
