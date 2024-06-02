/*
 * linux/fs/binfmt_cgc.c
 * Copyright (c) 2014 Jason L. Wright (jason@thought.net)
 *
 * Functions/module to load binaries targetting the DARPA Cyber Grand Challenge.
 * CGCOS binaries most thoroughly resemble static ELF binaries, thus this
 * code is derived from:
 *
 * linux/fs/binfmt_elf.c
 *
 * These are the functions used to load ELF format executables as used
 * on SVr4 machines.  Information on the format may be found in the book
 * "UNIX SYSTEM V RELEASE 4 Programmers Guide: Ansi C and Programming Support
 * Tools".
 *
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com).
 */

/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2024 Vitaly Chipounov
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

#ifndef __CGC_LOADER_H__
#define __CGC_LOADER_H__

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>

#define TASK_SIZE 0xC0000000
#define PAGE_SIZE 0x1000

// The stack must be outside of the exclusion range so that
// the binary can use syscalls in its shellcode.
#define STACK_TOP  0xaaaab000
#define STACK_SIZE 0x800000

#define INTERCEPT_EXCLUSION_START 0xb0000000
#define INTERCEPT_EXCLUSION_SIZE  0x10000000

#define BAD_ADDR(x) ((unsigned long) (x) >= TASK_SIZE)

#define CGC_MAGIC_PAGE    0x4347c000
#define CGC_MIN_PAGE_SIZE 4096
#define CGC_MIN_ALIGN     CGC_MIN_PAGE_SIZE

#define CGC_PAGESTART(_v)  ((_v) & ~(CGC_MIN_ALIGN - 1))
#define CGC_PAGEOFFSET(_v) ((_v) & (CGC_MIN_ALIGN - 1))
#define CGC_PAGEALIGN(_v)  (((_v) + CGC_MIN_ALIGN - 1) & ~(CGC_MIN_ALIGN - 1))

#define ERR_PTR(err) ((void *) ((long) (err)))
#define PTR_ERR(ptr) ((long) (ptr))
#define IS_ERR(ptr)  ((unsigned long) (ptr) > (unsigned long) (-1000))

typedef int (*cgc_main_t)();
typedef void (*sigsys_handler_t)(int num, siginfo_t *info, void *ucontext);

void launch_binary(uintptr_t stack, uintptr_t magic, cgc_main_t entry);
int init_intercept(sigsys_handler_t handler, char *intercept_flag, uintptr_t exclusion_start, uintptr_t exclusion_size);
int init_stack(uintptr_t top, uintptr_t size);
int init_magic_page(uintptr_t start, size_t size);
int load_cgcos_binary(int fd, uint32_t *entry);

#endif