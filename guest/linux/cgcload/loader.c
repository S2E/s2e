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
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "cgc.h"
#include "loader.h"

static uintptr_t cgc_map(int filep, struct CGC32_phdr *phdr, int prot, int type) {
    uintptr_t addr, zaddr;
    uintptr_t lo, hi;
    off_t off = 0;
    unsigned long size = 0;
    int ret = 0;

    if (phdr->p_filesz == 0 && phdr->p_memsz == 0) {
        return 0;
    }

    if (phdr->p_filesz > 0) {
        off = CGC_PAGESTART(phdr->p_offset);
        size = CGC_PAGEALIGN(phdr->p_filesz + CGC_PAGEOFFSET(phdr->p_vaddr));
        // Map in the part of the binary corresponding to filesz.
        addr = (uintptr_t) mmap((void *) (uintptr_t) CGC_PAGESTART(phdr->p_vaddr), size, prot, type, filep, off);
        if ((void *) addr == MAP_FAILED) {
            return addr;
        }

        lo = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_filesz);
        hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
    } else {
        // For 0 filesz, we have to include the first page as bss.
        lo = CGC_PAGESTART(phdr->p_vaddr + phdr->p_filesz);
        hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
    }

    // Map anon pages for the rest (no prefault).
    if ((hi - lo) > 0) {
        size = hi - lo;
        zaddr = (uintptr_t) mmap((void *) lo, size, prot, type | MAP_ANONYMOUS, 0, 0);
        if ((void *) zaddr == MAP_FAILED) {
            return zaddr;
        }
    }

    lo = phdr->p_vaddr + phdr->p_filesz;
    hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
    if ((hi - lo) > 0) {
        uintptr_t plo = CGC_PAGESTART(lo);
        ret = mprotect((void *) plo, hi - plo, PROT_READ | PROT_WRITE);
        if (ret < 0) {
            exit(-1);
        }

        // Clear remainder of the page to avoid garbage data from the file.
        memset((void *) lo, 0, hi - lo);

        ret = mprotect((void *) plo, hi - plo, prot);
        if (ret < 0) {
            exit(-1);
        }
    }

    return addr;
}

int load_cgcos_binary(int fd, uint32_t *entry) {
    int ret = -1;
    struct CGC32_hdr hdr;
    struct CGC32_phdr *phdrs = NULL;
    unsigned int sz;
    unsigned long start_code, end_code, start_data, end_data;
    unsigned long bss, brk;

    ssize_t ssz = read(fd, &hdr, sizeof(hdr));
    if (ssz != sizeof(hdr)) {
        fprintf(stderr, "could not read header\n");
        goto out;
    }

    if (hdr.ci_mag0 != 0x7f || hdr.ci_mag1 != 'C' || hdr.ci_mag2 != 'G' || hdr.ci_mag3 != 'C' || hdr.ci_class != 1 ||
        hdr.ci_data != 1 || hdr.ci_version != 1 || hdr.ci_osabi != 'C' || hdr.ci_abivers != 1 || hdr.c_type != 2 ||
        hdr.c_machine != 3 || hdr.c_version != 1 || hdr.c_flags != 0 || hdr.c_phentsize != sizeof(struct CGC32_phdr) ||
        hdr.c_phnum < 1 || hdr.c_phnum > 65536U / sizeof(struct CGC32_phdr)) {
        goto out;
    }

    sz = hdr.c_phnum * sizeof(struct CGC32_phdr);
    phdrs = malloc(sz);
    if (!phdrs) {
        goto out;
    }

    ssz = read(fd, phdrs, sz);
    if (ssz != sz) {
        goto out;
    }

    bss = brk = 0;
    start_code = ~0UL;
    end_code = start_data = end_data = 0;

    for (int i = 0; i < hdr.c_phnum; i++) {
        struct CGC32_phdr *phdr = &phdrs[i];

        int prot, flags;
        unsigned long k;

        switch (phdr->p_type) {
            case PT_NULL:
            case PT_LOAD:
            case PT_PHDR:
            case PT_CGCPOV2:
                break;
            default:
                fprintf(stderr, "invalid phdr->p_type 0x%x\n", phdr->p_type);
                ret = -ENOEXEC;
                goto out;
        }

        if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0) {
            continue;
        }

        prot = 0;
        if (phdr->p_flags & CPF_R) {
            prot |= PROT_READ;
        } else {
            ret = -EINVAL;
            goto out;
        }

        if (phdr->p_flags & CPF_W) {
            prot |= PROT_WRITE;
        }
        if (phdr->p_flags & CPF_X) {
            prot |= PROT_EXEC;
        }

        flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_FIXED;

        if (phdr->p_vaddr < start_code) {
            start_code = phdr->p_vaddr;
        }
        if (start_data < phdr->p_vaddr) {
            start_data = phdr->p_vaddr;
        }

        /*
         * Check to see if the section's size will overflow the
         * allowed task size. Note that p_filesz must always be
         * <= p_memsz so it is only necessary to check p_memsz.
         */
        if (BAD_ADDR(phdr->p_vaddr) || phdr->p_filesz > phdr->p_memsz || phdr->p_memsz > TASK_SIZE ||
            TASK_SIZE - phdr->p_memsz < phdr->p_vaddr) {
            /* set_brk can never work. avoid overflows. */
            ret = -EINVAL;
            goto out;
        }

        k = cgc_map(fd, phdr, prot, flags);
        if (BAD_ADDR(k)) {
            ret = IS_ERR((void *) k) ? PTR_ERR((void *) k) : -EINVAL;
            goto out;
        }

        k = phdr->p_vaddr + phdr->p_filesz;
        if (k > bss) {
            bss = k;
        }

        if ((phdr->p_flags & CPF_X) && end_code < k) {
            end_code = k;
        }

        if (end_data < k) {
            end_data = k;
        }

        k = phdr->p_vaddr + phdr->p_memsz;
        if (k > brk) {
            brk = k;
        }
    }

    bss = brk;

    *entry = hdr.c_entry;

    ret = 0;

out:
    return ret;
}

int init_magic_page(uintptr_t start, size_t size) {
    char *magic = mmap((void *) start, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    if (magic != (void *) CGC_MAGIC_PAGE) {
        goto out;
    }

    for (int i = 0; i < size; ++i) {
        magic[i] = rand();
    }

    strcpy(magic, "cgc{flag}");

    if (mprotect(magic, size, PROT_READ) < 0) {
        goto out;
    }

    return 0;

out:
    if (magic) {
        munmap(magic, size);
    }

    return -1;
}

/// @brief CGC stack has to be RWX and at a specific location.
int init_stack(uintptr_t top, uintptr_t size) {
    uintptr_t base = top - size;
    void *stack;

    stack =
        mmap((void *) base, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);

    if ((void *) stack == MAP_FAILED) {
        return -1;
    }

    if (stack != (void *) base) {
        munmap((void *) base, size);
        return -2;
    }

    return 0;
}

/// @brief Initializes syscall interception. This requires a recent kernel.
/// Parameters specify the exclusion range. Syscalls will not be intercepted there.
int init_intercept(sigsys_handler_t handler, char *intercept_flag, uintptr_t exclusion_start,
                   uintptr_t exclusion_size) {
    int ret = -1;
    struct sigaction new_action = {0};
    new_action.sa_flags = SA_SIGINFO;
    new_action.sa_sigaction = handler;
    sigemptyset(&new_action.sa_mask);

    ret = sigaction(SIGSYS, &new_action, 0);
    if (ret < 0) {
        fprintf(stderr, "could not set sigaction\n");
        goto out;
    }

    ret = prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, exclusion_start, exclusion_size, intercept_flag);
    if (ret < 0) {
        fprintf(stderr, "could not set prctl\n");
        goto out;
    }

    ret = 0;

out:
    return ret;
}
