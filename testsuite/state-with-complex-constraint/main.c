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
#include <stdlib.h>
#include <stdio.h>

const uint64_t FNV_PRIME = 1099511628211ULL;
const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;

uint64_t fnv1a_64(const uint64_t* data, size_t length) {
    uint64_t hash = FNV_OFFSET_BASIS;

    for (size_t i = 0; i < length; i++) {
        hash ^= (uint64_t)data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

static void test_fork_simple(void) {
    char buffer[0x10];
    int sym_int = 0;
    s2e_make_symbolic(&sym_int, sizeof(int), "varne0");
    
    printf("This is a test for calling printf");
    malloc(0x123);
    // Each of the two states should fork twice here,
    // resulting in a total of four states.
    if((sym_int & 0x1223) > 0) {
        /*
    if(fnv1a_64(buffer, 1) == 0xdead) {
        s2e_printf("This is state %d here", s2e_get_path_id());
    }else{
        exit(0);
    }
         */
        s2e_printf("This is state %d here", s2e_get_path_id());
    }
        s2e_printf("This is state %d here", s2e_get_path_id());
}

int main(int argc, char **argv) {
    test_fork_simple();
    return 0;
}
