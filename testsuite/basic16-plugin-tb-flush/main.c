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
/// Makes the TBCoverageTracer plugin flush the TB cache from an instruction
/// handler, which it defers until the next TB lookup, and checks that the guest
/// keeps running correctly afterwards.

#include <s2e/s2e.h>
#include <stdint.h>

// The commands of TBCoverageTracer.
enum { TRACE_ENABLE = 0, TRACE_DISABLE = 1 };

static uint32_t work(uint32_t seed) {
    uint32_t ret = seed;
    for (int i = 0; i < 1000; ++i) {
        ret = ret * 31 + i;
    }
    return ret;
}

int main(int argc, char **argv) {
    uint32_t first = work(1);

    for (int i = 0; i < 4; ++i) {
        int command = (i & 1) ? TRACE_DISABLE : TRACE_ENABLE;

        s2e_invoke_plugin("TBCoverageTracer", &command, sizeof(command));

        if (work(1) != first) {
            s2e_printf("FAILED: iteration %d computed a different value\n", i);
            return 1;
        }
    }

    s2e_printf("All good\n");
    return 0;
}
