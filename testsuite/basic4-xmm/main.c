// Copyright (c) 2019, Cyberhaven
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

#include <inttypes.h>
#include <s2e/s2e.h>

static void test_xmm(void) {
    uint64_t lo1 = 111111111111L;
    uint64_t hi1 = 222222222222L;
    uint64_t lo2, hi2;

    s2e_make_symbolic(&lo1, sizeof(lo1), "lo1");
    s2e_make_symbolic(&hi1, sizeof(hi1), "hi1");

    __asm__ __volatile__("movq    %3, %%xmm0      ;" // set high 64 bits
                         "pslldq  $8, %%xmm0      ;" // shift left 64 bits
                         "movsd   %2, %%xmm0      ;" // set low 64 bits
                                                     // operate on 128 bit register
                         "movq    %%xmm0, %0      ;" // get low 64 bits
                         "movhlps %%xmm0, %%xmm0  ;" // move high to low
                         "movq    %%xmm0, %1      ;" // get high 64 bits
                         : "=x"(lo2), "=x"(hi2)
                         : "x"(lo1), "x"(hi1)
                         : "%xmm0");

    if (lo1 == lo2 && hi1 == hi2) {
        s2e_printf("Good");
    } else {
        // This should not happen
        s2e_printf("Bad");
    }
}

int main(int argc, char **argv) {
    test_xmm();
    return 0;
}
