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

#include <s2e/s2e.h>
#include <stdio.h>

int main(int argc, char **argv) {
    // Set this to 10 to force concolic value recomputation in ExecutionState:addConstraint
    int var = 10;
    s2e_make_symbolic(&var, sizeof(var), "var");

    // Note that it's not possible to use "var == 10" because the compiler
    // will force a fork during expression evaluation, thereby concretizing it.
    s2e_assume(var - 10);

    if (var == 10) {
        // This branch is infeasible after s2e_assume
        s2e_printf("Equals 10");
    } else {
        s2e_printf("Not equals 10");
    }

    return 0;
}
