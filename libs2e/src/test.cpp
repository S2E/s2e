///
/// Copyright (C) 2015-2017, Cyberhaven
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

#include <stdio.h>

#include <cpu/exec.h>

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
