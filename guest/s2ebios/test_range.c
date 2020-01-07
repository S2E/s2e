/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2013 Dependable Systems Laboratory, EPFL
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

#include <s2e/s2e.h>

void test_range1() {
    uintptr_t value = 123, low, high;
    s2e_make_symbolic(&value, sizeof(value), "value");
    if (value > 10222) {
        s2e_get_range(value, &low, &high);
        s2e_print_expression("low", low);
        s2e_print_expression("high", high);
        s2e_assert(low == 10223);
        s2e_assert(high == (uint32_t) -1);
    } else {
        s2e_get_range(value, &low, &high);
        s2e_print_expression("low", low);
        s2e_print_expression("high", high);
        s2e_assert(low == 0);
        s2e_assert(high == 10222);
    }
    s2e_assert(s2e_get_constraint_count(value) == 1);
    s2e_kill_state(0, "done");
}

void test_constraints1() {
    uint32_t value = 123;
    s2e_make_symbolic(&value, sizeof(value), "value");
    s2e_assert(s2e_get_constraint_count(value) == 0);

    if (value > 10) {
        s2e_assert(s2e_get_constraint_count(value) == 1);
        if (value == 309) {
            s2e_print_expression("value", value);
        }
        s2e_assert(s2e_get_constraint_count(value) == 2);
    } else {
        s2e_assert(s2e_get_constraint_count(value) == 1);
        if (value == 3) {
            s2e_print_expression("value", value);
        }
        s2e_assert(s2e_get_constraint_count(value) == 2);
    }

    s2e_kill_state(0, "done");
}
