///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_SYSCALLS_H
#define S2E_KVM_SYSCALLS_H

#include <fsigc++/fsigc++.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>

typedef int (*open_t)(const char *pathname, int flags, mode_t mode);
typedef int (*close_t)(int fd);
typedef int (*ioctl_t)(int d, int request, ...);
typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef int (*dup_t)(int fd);

typedef int (*poll_t)(struct pollfd *fds, nfds_t nfds, int timeout);
typedef int (*select_t)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

typedef void (*exit_t)(int ret) __attribute__((__noreturn__));

typedef void *(*mmap_t)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
typedef void *(*mmap64_t)(void *addr, size_t len, int prot, int flags, int fd, off64_t offset);
typedef int (*madvise_t)(void *addr, size_t len, int advice);

typedef int (*printf_t)(const char *fmt, ...);
typedef int (*fprintf_t)(FILE *fp, const char *fmt, ...);

namespace s2e {

class SyscallEvents {
public:
    // Signal emitted when exit() is invoked
    sigc::signal<void, int> onExit;

    // Signal emitted when select is called
    sigc::signal<void> onSelect;
};

extern SyscallEvents g_syscalls;
} // namespace s2e

extern "C" {
extern exit_t g_original_exit;
extern ioctl_t g_original_ioctl;
extern open_t g_original_open;
extern mmap_t g_original_mmap;
extern mmap_t g_original_mmap64;
}

#endif
