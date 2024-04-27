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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

#include "loader.h"

#include <s2e/monitors/commands/decree.h>
#include <s2e/s2e.h>

static char s_intercept = SYSCALL_DISPATCH_FILTER_BLOCK;
static bool s_enable_seeds = false;
static bool s_enable_symbex = false;

enum cgc_syscall_id_t {
    CGC_SYSCALL_NULL,
    CGC_SYSCALL_TERMINATE,
    CGC_SYSCALL_TRANSMIT,
    CGC_SYSCALL_RECEIVE,
    CGC_SYSCALL_FDWAIT,
    CGC_SYSCALL_ALLOCATE,
    CGC_SYSCALL_DEALLOCATE,
    CGC_SYSCALL_RANDOM
};

int handle_null() {
    return 0;
}

void handle_terminate(uint32_t exit_code) {
    exit(exit_code);
}

int handle_transmit(int fd, const char *buf, size_t len, size_t *written) {
    ssize_t sz = 0;
    int ret = 0;
    size_t orig_len = len; // remember original symbolic size

    if (s_enable_symbex) {
        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER;
        cmd.SymbolicBuffer.ptr_addr = (uintptr_t) buf;
        cmd.SymbolicBuffer.size_addr = (uintptr_t) &len;

        __s2e_touch_buffer(buf, sizeof(*buf));
        __s2e_touch_buffer(&len, sizeof(len));
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    }

    sz = write(fd, buf, len);
    if (sz >= 0) {
        if (written) {
            *written = sz;
        }
        ret = 0;
    } else {
        ret = (int) sz;
        goto out;
    }

    if (s_enable_symbex) {
        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_WRITE_DATA;
        cmd.WriteData.fd = fd;
        cmd.WriteData.buffer = (uintptr_t) buf;
        cmd.WriteData.buffer_size_addr = (uintptr_t) &sz;
        cmd.WriteData.size_expr_addr = (uintptr_t) &orig_len;

        __s2e_touch_buffer(buf, sz);
        __s2e_touch_buffer(&sz, sizeof(sz));
        __s2e_touch_buffer(&orig_len, sizeof(orig_len));
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    }

out:
    return ret;
}

int handle_receive_internal(int fd, char *buf, size_t len, size_t *read_count) {
    int ret = 0;
    ssize_t sz = read(fd, buf, len);
    if (sz >= 0) {
        *read_count = sz;
        goto out;
    }
    ret = (int) sz;
out:
    return ret;
}

int handle_receive(int fd, char *buf, size_t len, size_t *read_count) {
    int ret = 0;
    if (!s_enable_symbex) {
        return handle_receive_internal(fd, buf, len, read_count);
    }

    if (s_enable_seeds) {
        ret = handle_receive_internal(fd, buf, len, read_count);
        if (ret < 0) {
            return ret;
        }

        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_READ_DATA_POST;
        cmd.DataPost.fd = fd;
        cmd.DataPost.buffer = (uintptr_t) buf;
        cmd.DataPost.buffer_size = *read_count;

        __s2e_touch_buffer(buf, *read_count);
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    } else {
        size_t orig_len = len; // remember original symbolic size

        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER;
        cmd.SymbolicBuffer.ptr_addr = (uintptr_t) buf;
        cmd.SymbolicBuffer.size_addr = (uintptr_t) &len;

        __s2e_touch_buffer(buf, sizeof(*buf));
        __s2e_touch_buffer(&len, sizeof(len));
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));

        memset(&cmd, 0, sizeof(cmd));
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_READ_DATA;
        cmd.Data.fd = fd;
        cmd.Data.buffer = (uintptr_t) buf;
        cmd.Data.buffer_size = len;
        cmd.Data.size_expr_addr = (uintptr_t) &orig_len;
        cmd.Data.result_addr = (uintptr_t) read_count;

        __s2e_touch_buffer(buf, len);
        __s2e_touch_buffer(&orig_len, sizeof(orig_len));
        __s2e_touch_buffer(&ret, sizeof(ret));
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    }

    return ret;
}

int handle_fdwait(int nfds, fd_set *readfds, fd_set *writefds, struct timeval *timeout, int *readyfds) {
    int invoke_orig = 1;
    int ret = 0, res = 0;

    if (s_enable_symbex) {
        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_FD_WAIT;
        cmd.FDWait.has_timeout = timeout != NULL;
        cmd.FDWait.tv_sec = timeout->tv_sec;
        cmd.FDWait.tv_nsec = timeout->tv_usec;
        cmd.FDWait.nfds = nfds;
        cmd.FDWait.invoke_orig = invoke_orig;
        cmd.FDWait.result = nfds;

        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));

        invoke_orig = cmd.FDWait.invoke_orig;

        res = cmd.FDWait.result;
    }

    if (invoke_orig) {
        res = select(nfds, readfds, writefds, NULL, timeout);
        if (res >= 0) {
            res = 0;
            *readyfds = res;
            goto out;
        }
    }

    ret = res;
out:
    return ret;
}

int handle_allocate(size_t len, int exec, void **addr) {
    int prot = PROT_READ | PROT_WRITE;
    if (exec) {
        prot |= PROT_EXEC;
    }
    void *ret_addr = mmap(NULL, len, prot, MAP_ANON | MAP_PRIVATE, 0, 0);
    if (ret_addr == MAP_FAILED) {
        return -EFAULT;
    } else {
        *addr = ret_addr;
        return 0;
    }
}

int handle_deallocate(void *ptr, size_t len) {
    return munmap(ptr, len);
}

int handle_random(char *buffer, size_t count, size_t *rnd_out) {
    for (size_t i = 0; i < count; ++i) {
        buffer[i] = (char) random();
    }
    *rnd_out = count;

    if (s_enable_symbex) {
        struct S2E_DECREEMON_COMMAND cmd = {0};
        cmd.version = S2E_DECREEMON_COMMAND_VERSION;
        cmd.Command = DECREE_RANDOM;
        cmd.Random.buffer = (uintptr_t) buffer;
        cmd.Random.buffer_size = count;

        __s2e_touch_buffer(buffer, count);
        s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    }

    return 0;
}

/// @brief This is the syscall signal handler.
/// When the CGC binary executes a syscall instruction (int 0x80),
/// the kernel sends a SIGSYS signal that is handled here.
// Helper functions for each syscall
static void sigsys_handler(int num, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *) ucontext;
    enum cgc_syscall_id_t sys_num = (enum cgc_syscall_id_t) ctx->uc_mcontext.gregs[REG_EAX];

    // Syscall parameters
    uint32_t p1 = ctx->uc_mcontext.gregs[REG_EBX];
    uint32_t p2 = ctx->uc_mcontext.gregs[REG_ECX];
    uint32_t p3 = ctx->uc_mcontext.gregs[REG_EDX];
    uint32_t p4 = ctx->uc_mcontext.gregs[REG_ESI];
    uint32_t p5 = ctx->uc_mcontext.gregs[REG_EDI];

    // Disable syscall interception for native syscall invocation
    s_intercept = SYSCALL_DISPATCH_FILTER_ALLOW;

    int result = 0;
    switch (sys_num) {
        case CGC_SYSCALL_NULL:
            result = handle_null();
            break;
        case CGC_SYSCALL_TERMINATE:
            handle_terminate(p1);
            break;
        case CGC_SYSCALL_TRANSMIT:
            result = handle_transmit(p1, (char *) p2, p3, (size_t *) p4);
            break;
        case CGC_SYSCALL_RECEIVE:
            result = handle_receive(p1, (char *) p2, p3, (size_t *) p4);
            break;
        case CGC_SYSCALL_FDWAIT:
            result = handle_fdwait(p1, (fd_set *) p2, (fd_set *) p3, (struct timeval *) p4, (int *) p5);
            break;
        case CGC_SYSCALL_ALLOCATE:
            result = handle_allocate(p1, p2, (void **) p3);
            break;
        case CGC_SYSCALL_DEALLOCATE:
            result = handle_deallocate((void *) p1, p2);
            break;
        case CGC_SYSCALL_RANDOM:
            result = handle_random((char *) p1, p2, (size_t *) p3);
            break;
        default:
            exit(-1000); // Unknown syscall, force exit
    }

    // Set result in EAX register after handling syscall
    ctx->uc_mcontext.gregs[REG_EAX] = result;

    // Re-enable syscall interception
    s_intercept = SYSCALL_DISPATCH_FILTER_BLOCK;
}

int main(int argc, const char **argv) {
    int fd = 0;
    int ret = -1;
    uint32_t entry = 0;

    const char *cmd = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--enable-seeds") == 0) {
            s_enable_seeds = true;
        } else if (strcmp(argv[i], "--enable-s2e") == 0) {
            s_enable_symbex = true;
        } else {
            // Assume any other argument is potentially a filename
            cmd = argv[i];
            break;
        }
    }

    if (cmd == NULL) {
        fprintf(stderr, "Usage: %s [--enable-seeds|--enable-s2e] /path/to/cgc/binary\n", argv[0]);
        goto err;
    }

    fd = open(cmd, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "could not open %s\n", cmd);
        goto err;
    }

    ret = load_cgcos_binary(fd, &entry);
    if (ret < 0) {
        fprintf(stderr, "could not load binary");
        goto err;
    }

    ret = init_magic_page(CGC_MAGIC_PAGE, CGC_MIN_PAGE_SIZE);
    if (ret < 0) {
        fprintf(stderr, "could not init magic page\n");
        goto err;
    }

    ret = init_stack(STACK_TOP, STACK_SIZE);
    if (ret < 0) {
        fprintf(stderr, "could not init stack\n");
        goto err;
    }

    ret = init_intercept(sigsys_handler, &s_intercept, INTERCEPT_EXCLUSION_START, INTERCEPT_EXCLUSION_SIZE);
    if (ret < 0) {
        fprintf(stderr, "could not init syscall interception\n");
        goto err;
    }

    launch_binary(STACK_TOP, CGC_MAGIC_PAGE, (cgc_main_t) entry);
    ret = 0;

err:
    if (fd >= 0) {
        close(fd);
    }

    return ret;
}
