/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TCG_MEMOPIDX

#define TCG_MEMOPIDX

#include <assert.h>
#include <inttypes.h>

#include "tcg-memop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Combine the MemOp and mmu_idx parameters into a single value.  */
typedef uint32_t MemOpIdx;

/**
 * make_memop_idx
 * @op: memory operation
 * @idx: mmu index
 *
 * Encode these values into a single parameter.
 */
static inline MemOpIdx make_memop_idx(MemOp op, unsigned idx) {
    assert(idx <= 15);
    return (op << 4) | idx;
}

/**
 * get_memop
 * @oi: combined op/idx parameter
 *
 * Extract the memory operation from the combined value.
 */
static inline MemOp get_memop(MemOpIdx oi) {
    return (MemOp) (oi >> 4);
}

/**
 * get_mmuidx
 * @oi: combined op/idx parameter
 *
 * Extract the mmu index from the combined value.
 */
static inline unsigned get_mmuidx(MemOpIdx oi) {
    return oi & 15;
}

#ifdef __cplusplus
}
#endif

#endif