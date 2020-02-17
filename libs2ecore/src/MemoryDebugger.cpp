///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

// Enable this to debug memory corruptions
// #define S2E_DEBUG_MEMORY

#ifdef S2E_DEBUG_MEMORY
#ifdef __linux__

#ifndef __APPLE__
#include <malloc.h>
#endif

#include <cxxabi.h>
#include <execinfo.h>
#include <memory.h>
#include <new>
#include <stdlib.h>

static FILE *s_mallocfp = nullptr;

static void init_mem_debug() {
    if (s_mallocfp) {
        return;
    }

    s_mallocfp = fopen("mem.log", "w");
    if (!s_mallocfp) {
        fprintf(stderr, "Could not init malloc trace log\n");
        exit(-1);
    }
}

static void mem_backtrace(const char *type, void *ptr, unsigned sz) {
    unsigned int max_frames = 63;
    void *addrlist[max_frames + 1];

    fprintf(s_mallocfp, "%s a=%p sz=%#x ", type, ptr, sz);

    // retrieve current stack addresses
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void *));

    if (addrlen == 0) {
        return;
    }

    for (int i = 1; i < addrlen; i++) {
        fprintf(s_mallocfp, "%p ", addrlist[i]);
    }

    fprintf(s_mallocfp, "\n");
}

void *operator new(size_t s) throw(std::bad_alloc) {
    init_mem_debug();
    void *ret = malloc(s);
    if (!ret) {
        throw std::bad_alloc();
    }

    memset(ret, 0xAA, s);
    mem_backtrace("A", ret, s);
    return ret;
}

void *operator new[](size_t s) throw(std::bad_alloc) {
    init_mem_debug();
    void *ret = malloc(s);
    if (!ret) {
        throw std::bad_alloc();
    }

    memset(ret, 0xAA, s);
    mem_backtrace("A", ret, s);
    return ret;
}

void operator delete(void *pvMem) throw() {
    init_mem_debug();
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
    mem_backtrace("D", pvMem, s);
}

void operator delete[](void *pvMem) throw() {
    init_mem_debug();
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
    mem_backtrace("D", pvMem, s);
}
#endif

#endif
