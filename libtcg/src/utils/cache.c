// Copyright (c) 2023 Vitaly Chipounov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <unistd.h>

#include <tcg/utils/cache.h>

int g_icache_linesize = 0;
int g_dcache_linesize = 0;

static int sys_cache_info(int *isize, int *dsize) {
    int ret = (int) sysconf(_SC_LEVEL1_ICACHE_LINESIZE);
    if (ret > 0) {
        *isize = ret;
    } else {
        return -1;
    }

    ret = (int) sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (ret > 0) {
        *dsize = ret;
    } else {
        return -2;
    }

    return 0;
}

int init_cache_info() {
    return sys_cache_info(&g_icache_linesize, &g_dcache_linesize);
}
