///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2017, Cyberhaven
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
///

#include <cpu/i386/cpu.h>

#include <stdio.h>
#include <string.h>

#define ALIGN_UP(n, align) (((n) + (align) -1) - ((n) + (align) -1) % (align))

static const unsigned STACK_SIZE = 0x100000;

extern CPUX86State myenv;
extern char *g_syscall_transmit_data;
extern size_t g_syscall_transmit_size;
extern int g_syscall_transmit_fd;

static inline void reset(uint8_t *stack) {
    myenv.regs[R_ESP] = (target_ulong)(stack + STACK_SIZE - 0x200000);
}

static inline void push(uintptr_t val) {
    myenv.regs[R_ESP] -= sizeof(uintptr_t);
    *(uintptr_t *) myenv.regs[R_ESP] = (uintptr_t) val;
}

static inline char *push_str(const char *s) {
    size_t len = strlen(s);
    myenv.regs[R_ESP] -= ALIGN_UP(len + 1, sizeof(uintptr_t));
    char *v = (char *) myenv.regs[R_ESP];
    strcpy(v, s);
    return v;
}

static inline uintptr_t pop() {
    uintptr_t ret = *(uintptr_t *) myenv.regs[R_ESP];
    myenv.regs[R_ESP] += sizeof(uintptr_t);
    return ret;
}

void detect_strlen(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_strcmp(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_strtol(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_printf(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_output_str(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_output_fd_str(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_output_str_len(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp);

void detect_output_fd_str_len(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                              FILE *fp);

void detect_output_fd_str_len_outlen(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                                     FILE *fp);
