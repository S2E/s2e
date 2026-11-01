// Copyright (c) 2026, Vitaly Chipounov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// @file
/// Forks 16 paths that each run code in KLEE and natively. The test runs with
/// flush-tbs-on-state-switch set to false, so that states share their TBs and
/// LLVM functions across state switches.

#include <s2e/s2e.h>
#include <stdint.h>

#define BRANCH_COUNT 4

/// Runs enough code to translate several TBs, which later states reuse.
static uint32_t work(uint32_t seed) {
    uint32_t ret = seed;
    for (int i = 0; i < 1000; ++i) {
        ret = ret * 31 + i;
    }
    return ret;
}

int main(int argc, char **argv) {
    uint8_t input[BRANCH_COUNT] = {0};
    uint32_t path = 0;
    uint32_t sum = 0;

    s2e_make_symbolic(input, sizeof(input), "input");

    for (int i = 0; i < BRANCH_COUNT; ++i) {
        if (input[i] > 100) {
            path |= 1U << i;
        }
        sum += work(path);
    }

    // The second computation runs in the state that the first one forked.
    uint32_t expected = 0;
    uint32_t prefix = 0;
    for (int i = 0; i < BRANCH_COUNT; ++i) {
        prefix |= path & (1U << i);
        expected += work(prefix);
    }

    if (sum == expected) {
        s2e_printf("Path %u\n", path);
    } else {
        s2e_printf("FAILED: path %u computed %#x instead of %#x\n", path, sum, expected);
    }

    return 0;
}
