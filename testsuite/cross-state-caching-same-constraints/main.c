// Copyright (c) 2023, GTISC
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
#include <string.h>

static void test_fork_simple(void) {
    char buffer[0x100];
    s2e_make_symbolic(buffer, sizeof(buffer), "buffer");

    s2e_fork(1);

    // Each of the two states should fork twice here,
    // resulting in a total of four states.
    if (!strcmp(buffer, "ABCD")) {
        s2e_printf("This is state %d here", s2e_get_path_id());
    } else if(strcmp(buffer, "ABCE")) {
        s2e_printf("This is state %d here", s2e_get_path_id());
    }else{
        exit(0);
    }
}

int main(int argc, char **argv) {
    test_fork_simple();
    return 0;
}
