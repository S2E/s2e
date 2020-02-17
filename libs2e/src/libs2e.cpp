///
/// Copyright (C) 2015-2017, Cyberhaven
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

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef __REDIRECT_NTH
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cpu/exec.h>
#include "s2e-kvm-trace.h"
#include "s2e-kvm.h"

#ifdef CONFIG_SYMBEX
#include <s2e/s2e_log.h>
#endif

#include "FileDescriptorManager.h"
#include "libs2e.h"
#include "syscalls.h"

namespace s2e {
SyscallEvents g_syscalls;
}

// TODO: make this an env variable
int g_trace = 0;

s2e::kvm::FileDescriptorManagerPtr g_fdm = std::make_shared<s2e::kvm::FileDescriptorManager>();

extern "C" {

open_t g_original_open;
int open64(const char *pathname, int flags, ...) {
    va_list list;
    va_start(list, flags);
    mode_t mode = va_arg(list, mode_t);
    va_end(list);

    if (!strcmp(pathname, "/dev/kvm")) {
        printf("Opening %s\n", pathname);

        s2e::kvm::IFilePtr kvm;

        if (g_trace) {
            kvm = s2e::kvm::KVMTrace::create();
        } else {
            kvm = s2e::kvm::S2EKVM::create();
        }

        if (!kvm) {
            return -1;
        }

        int fd = g_fdm->registerInterface(kvm);
        if (fd < 0) {
            printf("Could not register fake kvm file descriptor\n");
            exit(-1);
        }

        return fd;
    } else {
        return g_original_open(pathname, flags, mode);
    }
}

static close_t s_original_close;
int close64(int fd) {
    if (g_fdm->close(fd)) {
        return 0;
    } else {
        return s_original_close(fd);
    }
}

static write_t s_original_write;
ssize_t write(int fd, const void *buf, size_t count) {
    auto ifp = g_fdm->get(fd);
    if (ifp) {
        return ifp->sys_write(fd, buf, count);
    } else {
        return s_original_write(fd, buf, count);
    }
}

ioctl_t g_original_ioctl;
int ioctl(int fd, int request, uint64_t arg1) {
    auto ifp = g_fdm->get(fd);
    if (ifp) {
        return ifp->sys_ioctl(fd, request, arg1);
    } else {
        return g_original_ioctl(fd, request, arg1);
    }
}

static poll_t s_original_poll;
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    // TODO: do we actually have to request exit from here?
    return s_original_poll(fds, nfds, timeout);
}

static select_t s_original_select;
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int ret = s_original_select(nfds, readfds, writefds, exceptfds, timeout);
    s2e::g_syscalls.onSelect.emit();
    return ret;
}

exit_t g_original_exit;
void exit(int code) {
    s2e::g_syscalls.onExit.emit(code);
    g_original_exit(code);
}

#undef mmap

mmap_t g_original_mmap;
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    auto ifp = g_fdm->get(fd);
    if (ifp) {
        return ifp->sys_mmap(addr, len, prot, flags, fd, offset);
    } else {
        return g_original_mmap(addr, len, prot, flags, fd, offset);
    }
}

mmap64_t g_original_mmap64;
void *mmap64(void *addr, size_t len, int prot, int flags, int fd, off64_t offset) {
    auto ifp = g_fdm->get(fd);
    if (ifp) {
        return ifp->sys_mmap(addr, len, prot, flags, fd, offset);
    } else {
        return g_original_mmap64(addr, len, prot, flags, fd, offset);
    }
}

static dup_t s_original_dup;
int dup(int fd) {
    auto ifp = g_fdm->get(fd);
    if (ifp) {
        return g_fdm->registerInterface(ifp);
    } else {
        return s_original_dup(fd);
    }
}

static madvise_t s_original_madvise;
int madvise(void *addr, size_t len, int advice) {
    if (advice & MADV_DONTFORK) {
        // We must fork all memory for multi-core mode
        advice &= ~MADV_DONTFORK;
    }

    if (!advice) {
        return 0;
    }

    return s_original_madvise(addr, len, advice);
}

//////////////////////////////////////////////////
// Intercept process's print functions to redirect
// them to S2E's debug logs.

#ifdef CONFIG_SYMBEX
static printf_t s_original_printf;
int printf(const char *fmt, ...) {
    va_list vl;
    va_start(vl, fmt);
    int ret = vprintf(fmt, vl);
    va_end(vl);

    va_start(vl, fmt);
    s2e_vprintf(fmt, false, vl);
    va_end(vl);

    return ret;
}

static fprintf_t s_original_fprintf;
int fprintf(FILE *fp, const char *fmt, ...) {
    va_list vl;
    va_start(vl, fmt);
    int ret = vfprintf(fp, fmt, vl);
    va_end(vl);

    if (fp == stdout || fp == stderr) {
        va_start(vl, fmt);
        s2e_vprintf(fmt, false, vl);
        va_end(vl);
    }

    return ret;
}
#endif

///
/// \brief check_kvm_switch verifies that KVM mode is enabled.
///
/// It's a common mistake to preload libs2e.so but forget the --enable-kvm switch
///
/// \param argc command line arg count
/// \param argv command line arguments
/// \return true if kvm switch is found
///
static bool check_kvm_switch(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        if (strstr(argv[i], "-enable-kvm")) {
            return true;
        }
    }

    return false;
}

void libs2e_init_syscalls(void) {
    static bool inited = false;

    if (inited) {
        return;
    }

    g_original_open = (open_t) dlsym(RTLD_NEXT, "open64");
    s_original_close = (close_t) dlsym(RTLD_NEXT, "close64");
    g_original_ioctl = (ioctl_t) dlsym(RTLD_NEXT, "ioctl");
    s_original_write = (write_t) dlsym(RTLD_NEXT, "write");
    s_original_select = (select_t) dlsym(RTLD_NEXT, "select");
    s_original_poll = (poll_t) dlsym(RTLD_NEXT, "poll");
    g_original_exit = (exit_t) dlsym(RTLD_NEXT, "exit");
    g_original_mmap = (mmap_t) dlsym(RTLD_NEXT, "mmap");
    g_original_mmap64 = (mmap64_t) dlsym(RTLD_NEXT, "mmap64");
    s_original_madvise = (madvise_t) dlsym(RTLD_NEXT, "madvise");
    s_original_dup = (dup_t) dlsym(RTLD_NEXT, "dup");

#ifdef CONFIG_SYMBEX
    s_original_printf = (printf_t) dlsym(RTLD_NEXT, "printf");
    s_original_fprintf = (fprintf_t) dlsym(RTLD_NEXT, "fprintf");
#endif

    inited = true;
}

// ****************************
// Overriding __llibc_start_main
// ****************************

// The type of __libc_start_main
typedef int (*T_libc_start_main)(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void), void(*stack_end));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) __attribute__((noreturn));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) {

    T_libc_start_main orig_libc_start_main = (T_libc_start_main) dlsym(RTLD_NEXT, "__libc_start_main");

    libs2e_init_syscalls();

    // Hack when we are called from gdb or through a shell command
    if (strstr(ubp_av[0], "bash")) {
        (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
        exit(-1);
    }

    printf("Starting libs2e...\n");

    // libs2e might spawn other processes (e.g., from plugin code).
    // This will fail if we preload libs2e.so for these processes,
    // so we must remove this environment variable.
    unsetenv("LD_PRELOAD");

    // When libs2e is used with qemu, verify that enable-kvm switch
    // has been specified.
    if (strstr(ubp_av[0], "qemu") && !check_kvm_switch(argc, ubp_av)) {
        fprintf(stderr, "Please use -enable-kvm switch before starting QEMU\n");
        exit(-1);
    }

    if (!init_ram_size(argc, ubp_av)) {
        exit(-1);
    }

    (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    exit(1); // This is never reached
}
}
