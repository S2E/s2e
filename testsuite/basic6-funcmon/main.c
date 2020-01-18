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
#include <stdio.h>
#include <string.h>

// #define s2e_message s2e_printf
// #define s2e_printf printf

// Testcase scripts require that function name prefix be unique.
// Noinline is required, otherwise the compiler will remove the functions.

__attribute__((noinline)) static void func_a_single_path(void) {
    printf("%s", __FUNCTION__);
}

__attribute__((noinline)) static void func_b(void) {
    printf("%s", __FUNCTION__);
}

__attribute__((noinline)) static void func_c_single_path_nested(void) {
    printf("%s", __FUNCTION__);
    func_b();
    // Avoid tail call optimization
    printf("%s", __FUNCTION__);
}

__attribute__((noinline)) static void func_d_with_fork(void) {
    int c = 0;
    s2e_make_symbolic(&c, sizeof(c), __FUNCTION__);
    if (c) {
        s2e_printf("c is true");
    } else {
        s2e_printf("c is false");
    }
}

__attribute__((noinline)) static void func_e_skipped(void) {
    s2e_printf("This message must not appear");
}

int main(int argc, char **argv) {
    func_e_skipped();

    func_a_single_path();

    func_c_single_path_nested();

    func_d_with_fork();

    if (s2e_get_path_id() != 0) {
        s2e_kill_state(0, "done forked path");
    }

    return 0;
}
