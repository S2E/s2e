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
#include <s2e/function_models/commands.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>


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
    WCHAR a[] = L"SecretToMatch";
    WCHAR s[20] = {};
    s2e_make_symbolic(s, sizeof(s), "varne0");
    char* aa = (char*) a;
    s2e_printf("Buffer: %x %x %x %x\n", aa[0], aa[1], aa[2], aa[3]);
    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRCMPWIDTH;
    cmd.StrcmpWidth.str1 = (uintptr_t)a;
    cmd.StrcmpWidth.str2 = (uintptr_t)s;
    cmd.needOrigFunc = 1;
    cmd.StrcmpWidth.width = 2;
    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));
    if (!cmd.needOrigFunc)
    {
        if (cmd.StrcmpWidth.ret)
        {
            s2e_printf("String cmp return 1");
        }
        else
        {
            s2e_printf("String cmp return 0");
        }
    }
}

int main(int argc, char **argv) {
    test_fork_simple();
    return 0;
}
