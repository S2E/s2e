///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <stdio.h>

#include <cpu/exec.h>
#include <tcg/tcg.h>

#include "coroutine.h"

static Coroutine *s_coroutine;
static uint64_t s_max = 100 * 1000 * 1000;

static void fcn(void *p) {
    while (1) {
        coroutine_yield();
    }
}

// This tests the overhead of a coroutine context switch
static void test_coroutine() {
    s_coroutine = coroutine_create(fcn, 1 << 20);

    for (uint64_t i = 0; i < s_max; ++i) {
        coroutine_enter(s_coroutine, NULL);
    }
}

int main() {
    // cpu_gen_init();
    // tcg_prologue_init(&tcg_ctx);
    printf("Starting tests...\n");
    test_coroutine();

    return 0;
}
