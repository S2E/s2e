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

#ifndef TCGS2E_H
#define TCGS2E_H

#include <inttypes.h>
#include "tcg.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SYMBEX
static inline int tcg_is_dyngen_addr(void *addr) {
    uintptr_t a = (uintptr_t) addr;
    return (a >= (uintptr_t) tcg_ctx->code_gen_buffer) &&
           (a < ((uintptr_t) tcg_ctx->code_gen_buffer + (uintptr_t) tcg_ctx->code_gen_buffer_size));
}

void tcg_calc_regmask(TCGContext *s, uint64_t *rmask, uint64_t *wmask, uint64_t *accesses_mem);
#endif

#ifdef __cplusplus
}
#endif

#endif
