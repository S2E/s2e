///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <cpu/kvm.h>
#include "s2e-kvm-interface.h"

#ifdef CONFIG_SYMBEX
#include <s2e/s2e_log.h>
#endif

static open_t s_original_open;

int g_trace = 0;
int g_kvm_fd = -1;
int g_kvm_vm_fd = -1;
int g_kvm_vcpu_fd = -1;

int open64(const char *pathname, int flags, ...) {
    va_list list;
    va_start(list, flags);
    mode_t mode = va_arg(list, mode_t);
    va_end(list);

    if (!strcmp(pathname, "/dev/kvm")) {
        printf("Opening %s\n", pathname);
        int fd = s_original_open("/dev/null", flags, mode);
        if (fd < 0) {
            printf("Could not open fake kvm /dev/null\n");
            exit(-1);
        }

        g_kvm_fd = fd;
        return fd;
    } else {
        return s_original_open(pathname, flags, mode);
    }
}

static close_t s_original_close;
int close64(int fd) {
    if (fd == g_kvm_fd) {
        printf("close %d\n", fd);
        close(fd);
        g_kvm_fd = -1;
        return 0;
    } else {
        return s_original_close(fd);
    }
}

static write_t s_original_write;
ssize_t write(int fd, const void *buf, size_t count) {
    if (fd == g_kvm_fd || fd == g_kvm_vm_fd) {
        printf("write %d count=%ld\n", fd, count);
        exit(-1);
    } else {
        return s_original_write(fd, buf, count);
    }
}

static int handle_kvm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t) request) {
        case KVM_GET_API_VERSION:
            return s2e_kvm_get_api_version();

        case KVM_CHECK_EXTENSION:
            ret = s2e_kvm_check_extension(fd, arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_CREATE_VM: {
            int tmpfd = s2e_kvm_create_vm(fd);
            if (tmpfd < 0) {
                printf("Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
            g_kvm_vm_fd = tmpfd;
            ret = tmpfd;
        } break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = s2e_kvm_get_vcpu_mmap_size();
        } break;

        case KVM_GET_MSR_INDEX_LIST: {
            ret = s2e_kvm_get_msr_index_list(fd, (struct kvm_msr_list *) arg1);
        } break;

        case KVM_GET_SUPPORTED_CPUID: {
            ret = s2e_kvm_get_supported_cpuid(fd, (struct kvm_cpuid2 *) arg1);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_SET_TSS_ADDR: {
            ret = s2e_kvm_vm_set_tss_addr(fd, arg1);
        } break;

        case KVM_CREATE_VCPU: {
            ret = s2e_kvm_vm_create_vcpu(fd);
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            ret = s2e_kvm_vm_set_user_memory_region(fd, (struct kvm_userspace_memory_region *) arg1);
        } break;

        case KVM_SET_CLOCK: {
            ret = s2e_kvm_vm_set_clock(fd, (struct kvm_clock_data *) arg1);
        } break;

        case KVM_GET_CLOCK: {
            ret = s2e_kvm_vm_get_clock(fd, (struct kvm_clock_data *) arg1);
        } break;

        case KVM_ENABLE_CAP: {
            ret = s2e_kvm_vm_enable_cap(fd, (struct kvm_enable_cap *) arg1);
        } break;

        case KVM_IOEVENTFD: {
            ret = s2e_kvm_vm_ioeventfd(fd, (struct kvm_ioeventfd *) arg1);
        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = s2e_kvm_vm_set_identity_map_addr(fd, arg1);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = s2e_kvm_vm_get_dirty_log(fd, (struct kvm_dirty_log *) arg1);
        } break;

        case KVM_MEM_RW: {
            ret = s2e_kvm_vm_mem_rw(fd, (struct kvm_mem_rw *) arg1);
        } break;

        case KVM_FORCE_EXIT: {
            s2e_kvm_request_exit();
            ret = 0;
        } break;

        case KVM_MEM_REGISTER_FIXED_REGION: {
            ret = s2e_kvm_vm_register_fixed_region(fd, (struct kvm_fixed_region *) arg1);
        } break;

        case KVM_DISK_RW: {
            ret = s2e_kvm_vm_disk_rw(fd, (struct kvm_disk_rw *) arg1);
        } break;

        case KVM_DEV_SNAPSHOT: {
            ret = s2e_kvm_vm_dev_snapshot(fd, (struct kvm_dev_snapshot *) arg1);
        } break;

        case KVM_SET_CLOCK_SCALE: {
            ret = s2e_kvm_set_clock_scale_ptr(fd, (unsigned *) arg1);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vcpu_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = s2e_kvm_vcpu_get_clock(fd, (struct kvm_clock_data *) arg1);
        } break;

        case KVM_SET_CPUID2: {
            ret = s2e_kvm_vcpu_set_cpuid2(fd, (struct kvm_cpuid2 *) arg1);
        } break;

        case KVM_SET_SIGNAL_MASK: {
            ret = s2e_kvm_vcpu_set_signal_mask(fd, (struct kvm_signal_mask *) arg1);
        } break;

        /***********************************************/
        case KVM_SET_REGS: {
            ret = s2e_kvm_vcpu_set_regs(fd, (struct kvm_regs *) arg1);
        } break;

        case KVM_SET_FPU: {
            ret = s2e_kvm_vcpu_set_fpu(fd, (struct kvm_fpu *) arg1);
        } break;

        case KVM_SET_SREGS: {
            ret = s2e_kvm_vcpu_set_sregs(fd, (struct kvm_sregs *) arg1);
        } break;

        case KVM_SET_MSRS: {
            ret = s2e_kvm_vcpu_set_msrs(fd, (struct kvm_msrs *) arg1);
        } break;

        case KVM_SET_MP_STATE: {
            ret = s2e_kvm_vcpu_set_mp_state(fd, (struct kvm_mp_state *) arg1);
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            ret = s2e_kvm_vcpu_get_regs(fd, (struct kvm_regs *) arg1);
        } break;

        case KVM_GET_FPU: {
            ret = s2e_kvm_vcpu_get_fpu(fd, (struct kvm_fpu *) arg1);
        } break;

        case KVM_GET_SREGS: {
            ret = s2e_kvm_vcpu_get_sregs(fd, (struct kvm_sregs *) arg1);
        } break;

        case KVM_GET_MSRS: {
            ret = s2e_kvm_vcpu_get_msrs(fd, (struct kvm_msrs *) arg1);
        } break;

        case KVM_GET_MP_STATE: {
            ret = s2e_kvm_vcpu_get_mp_state(fd, (struct kvm_mp_state *) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return s2e_kvm_vcpu_run(fd);
        } break;

        case KVM_INTERRUPT: {
            ret = s2e_kvm_vcpu_interrupt(fd, (struct kvm_interrupt *) arg1);
        } break;

        case KVM_NMI: {
            ret = s2e_kvm_vcpu_nmi(fd);
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VCPU IOCTL vcpu %d request=%#x arg=%#" PRIx64 " ret=%#x\n", fd,
                    request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}

ioctl_t g_original_ioctl;
int ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    if (g_trace) {
        if (fd == g_kvm_fd) {
            // printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            // printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_vm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vcpu_fd) {
            ret = handle_kvm_vcpu_ioctl_trace(fd, request, arg1);
        } else {
            // printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    } else {
        if (fd == g_kvm_fd) {
            // printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            // printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_vm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vcpu_fd) {
            ret = handle_kvm_vcpu_ioctl(fd, request, arg1);
        } else {
            // printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    }

    return ret;
}

static poll_t s_original_poll;
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    // TODO: do we actually have to request exit from here?
    return s_original_poll(fds, nfds, timeout);
}

static select_t s_original_select;
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int ret = s_original_select(nfds, readfds, writefds, exceptfds, timeout);
    s2e_kvm_request_exit();
    return ret;
}

static exit_t s_original_exit;
void exit(int code) {
    s2e_kvm_request_process_exit(s_original_exit, code);
}

static mmap_t s_original_mmap;
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    if (fd < 0 || (fd != g_kvm_vcpu_fd)) {
        return s_original_mmap(addr, len, prot, flags, fd, offset);
    }

    int real_size = s2e_kvm_get_vcpu_mmap_size();
    assert(real_size == len);
    assert(g_kvm_vcpu_buffer);

    return g_kvm_vcpu_buffer;
}

static madvise_t s_original_madvise;
int madvise(void *addr, size_t len, int advice) {
    if (advice & MADV_DONTFORK) {
        // We must fork all memory for multi-core more
        advice &= ~MADV_DONTFORK;
    }

    if (!advice) {
        return 0;
    }

    return s_original_madvise(addr, len, advice);
}

//////////////////////////////////////////////////
// Intercept processe's print functions to redirect
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

    va_start(vl, fmt);
    s2e_vprintf(fmt, false, vl);
    va_end(vl);

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
    s_original_open = (open_t) dlsym(RTLD_NEXT, "open64");
    s_original_close = (close_t) dlsym(RTLD_NEXT, "close64");
    g_original_ioctl = (ioctl_t) dlsym(RTLD_NEXT, "ioctl");
    s_original_write = (write_t) dlsym(RTLD_NEXT, "write");
    s_original_select = (select_t) dlsym(RTLD_NEXT, "select");
    s_original_poll = (poll_t) dlsym(RTLD_NEXT, "poll");
    s_original_exit = (exit_t) dlsym(RTLD_NEXT, "exit");
    s_original_mmap = (mmap_t) dlsym(RTLD_NEXT, "mmap64");
    s_original_madvise = (madvise_t) dlsym(RTLD_NEXT, "madvise");

#ifdef CONFIG_SYMBEX
    s_original_printf = (printf_t) dlsym(RTLD_NEXT, "printf");
    s_original_fprintf = (fprintf_t) dlsym(RTLD_NEXT, "fprintf");
#endif

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
