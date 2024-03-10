/*
 *  User emulator execution
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <inttypes.h>

// clang-format off
#include <tcg/tcg.h>
#include <tcg/exec/helper-gen.h>
#include <tcg/cpu.h>
// clang-format on

#define ATOMIC_NAME(X) glue(glue(glue(cpu_atomic_##X, SUFFIX), END), _mmu)

#define ATOMIC_MMU_CLEANUP

#include "atomic_common.c.inc"

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

#if HAVE_CMPXCHG128 || HAVE_ATOMIC128
#define DATA_SIZE 16
#include "atomic_template.h"
#endif

// TODO: FIXME
void helper_st_i128(CPUArchState *env, uint64_t addr, Int128 val, MemOpIdx oi) {
    abort();
}

Int128 helper_ld_i128(CPUArchState *env, uint64_t addr, uint32_t oi) {
    abort();
    return int128_make64(0);
}