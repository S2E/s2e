// Copyright (c) 2020, Cyberhaven
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

#include <s2e/s2e.h>
#include <stdio.h>

#define DATA_SIZE 0x1000

// This must be aligned on a page boundary in order to avoid extra forks
// for overlapping accesses.
char g_data[DATA_SIZE] __attribute__((aligned(DATA_SIZE)));

int main(int argc, char **argv) {
    unsigned offset = 0;

    // Test 1: check that 1 byte symbolic access forks
    // the correct number of states.
    s2e_make_symbolic(&offset, sizeof(offset), "offset1");
    for (int i = 0; i < DATA_SIZE; ++i) {
        g_data[i] = (char) i;
    }

    if (offset < DATA_SIZE) {
        s2e_print_expression("value1", g_data[offset]);
    }

    if (s2e_get_path_id() != 0) {
        s2e_kill_state(0, "Terminated symbaddr1 path");
    }
}
