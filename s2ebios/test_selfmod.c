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

#include "inttypes.h"
#include "main.h"
#include "string.h"

/**
 *  Tests self-modifying code
 *
 *  Inputs: RDX=0x5b07e8d8c90406de
 *          RCX=start of buffer
 *  0x2e, 0x48, 0x31, 0x11, 0x90, 0xd9, 0x56, 0x53
 *  00000000  2E483111          xor [cs:rcx],rdx
 *  00000004  90                nop
 *  00000005  D95653            fst dword [rsi+0x53]
 *  ...
 *
 *  TODO: put assertions
 */
void test_selfmod1() {
    char code[] = {0x2e, 0x48, 0x31, 0x11, 0x90, 0xd9, 0x56, 0x53, 0x96, 0x37, 0x55, 0xd9,
                   0x90, 0xd9, 0x56, 0x43, 0x96, 0x37, 0x55, 0xe9, 0x90, 0xd9, 0x56, 0x73};

    void *exec_mem = (char *) 0x301bd;

    memset(exec_mem, 0xf4, 0x1000); // Put hlt everywhere
    memcpy(exec_mem, code, sizeof(code));

#ifdef __x86_64__
    __asm__ __volatile__("mov %0, %%rax\n"
                         "mov %%rax, %%rcx\n"
                         "mov $0x5b07e8d8c90406de, %%rdx\n"
                         "callq *%%rax\n" ::"a"(exec_mem));

#else
    s2e_message("test_selfmod1 not supported in 32-bits mode");
#endif
}
