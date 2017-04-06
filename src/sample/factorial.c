/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

/**
 *  This sample program illustrates equivalence checking with S2E.
 *  It contains two implementations of the factorial algorithm. Both
 *  implementations behave the same except in some corner cases.
 *  The main method calls the S2E custom instructions to perform
 *  equivalence checks.
 *
 *  Compile as follows:
 *  gcc -I /home/user/s2e/guest/include/ -std=c99 -o factorial factorial.c
 */

#include <inttypes.h>
#include <s2e/s2e.h>

/**
 *  Computes x!
 *  If x > max, computes max!
 */
uint64_t factorial1(uint64_t x, uint64_t max) {
    uint64_t ret = 1;
    for (uint64_t i = 1; i <= x && i <= max; ++i) {
        ret = ret * i;
    }
    return ret;
}

/**
 *  Computes x!
 *  If x > max, computes max!
 */
uint64_t factorial2(uint64_t x, uint64_t max) {
    if (x > max) {
        return max;
    }

    if (x == 1) {
        return x;
    }
    return x * factorial2(x - 1, max);
}

int main() {
    uint64_t x;
    uint64_t max = 10;

    // Make x symbolic
    s2e_make_symbolic(&x, sizeof(x), "x");

    uint64_t f1 = factorial1(x, max);
    uint64_t f2 = factorial2(x, max);

    // Check the equivalence of the two functions for each path
    s2e_assert(f1 == f2);

    // In case of success, terminate the state with the
    // appropriate message
    s2e_kill_state(0, "Success");
    return 0;
}
