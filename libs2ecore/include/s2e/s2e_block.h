///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef _S2E_BLOCK_H_

#define _S2E_BLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct S2EBlockDevice;

/* Disk-related copy on write */
int s2e_bdrv_read(struct S2EBlockDevice *bs, int64_t sector_num, uint8_t *buf, int nb_sectors);

int s2e_bdrv_write(struct S2EBlockDevice *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors);

void s2e_bdrv_fail();

extern struct S2EExecutionState **g_block_s2e_state;

#ifdef __cplusplus
}
#endif

#endif
