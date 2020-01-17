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

#include <ctype.h>
#include <inttypes.h>
#include <s2e/s2e.h>
#include <stdio.h>
#include <string.h>

// This is a reverse-engineering CTF challenge.
// When the player passes the correct flag on stdin, the challenge prints "you found it".
// This challenge will cause path explosion when ran with symbolic execution.
// There are two sources of path explosion: the scanf call and the decryption loop.
//
// In order to solve this challenge, a player would need to use S2E instrumentation in order
// to eliminate useless states:
// 1. Replace the scanf call with an instrumentation that would directly write symbolic data
//    to the buffer.
// 2. Kill the state as soon as is_good() returns false. This will prevent the loop from
//    causing further forks when we already know that the input is invalid.
//
// The testsuite automatically generates the required instrumentation in order to solve
// this challenge. Please refer to fix-config.sh and run-tests.tpl files for details.

static char s_flag[] = "pgs{frperg-synt}";

// We use noinline in order to easily locate and patch the function call at runtime.
// In a real challenge, the player would have to manually inspect the binary to
// figure out which addresses to use in the instrumentation.
__attribute__((noinline)) char rotate(char c) {
    if (c >= 'a' && c <= 'z') {
        c -= 'a';
        c += 13;
        c %= 26;
        c += 'a';
    }
    return c;
}

__attribute__((noinline)) int is_good(char a, char b) {
    return a == b;
}

int main(int argc, char **argv) {
    char buffer[30] = {0};
    int ret = scanf("%20s", buffer);
    if (ret != 1) {
        return -1;
    }

    int good = 1;
    int max_len = strlen(s_flag);
    int i = 0;
    for (i = 0; buffer[i] && i < max_len; ++i) {
        good &= is_good(s_flag[i], rotate(buffer[i]));
    }
    good &= i == max_len;

    if (good) {
        s2e_printf("you found it\n");
    } else {
        s2e_printf("you lost\n");
    }

    return 0;
}
