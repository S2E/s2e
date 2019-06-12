///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
