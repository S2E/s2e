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

#include <unistd.h>

#include <coroutine.h>
#include <cpu/ioport.h>
#include <cpu/kvm.h>
#include <cpu/memory.h>
#include <cpu/tb.h>
#include <inttypes.h>

#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <tcg/utils/log.h>
#include "s2e-kvm-vcpu.h"
#include "s2e-kvm-vm.h"
#include "s2e-kvm.h"

extern CPUX86State *env;

#if 0
#define SE_KVM_DEBUG_MMIO
#define SE_KVM_DEBUG_APIC
#define SE_KVM_DEBUG_IO

#define DPRINTF(...) fprintf(logfile, __VA_ARGS__)
#endif

namespace s2e {
namespace kvm {

static void signal_ioeventfd(int fd) {
    uint64_t val = 1;
    ssize_t ret = write(fd, &val, sizeof(val));
    if (ret != sizeof(val)) {
        fprintf(stderr, "ioeventfd: write to fd %d failed\n", fd);
    }
}

// This is an experimental feature
// #define ENABLE_RETRANSLATE

// This function aborts the execution of the current translation block.
// It is useful when the KVM client modifies the program counter during
// an I/O operation (e.g., VAPIC emulation).
static void abort_and_retranslate_if_needed() {
#ifdef ENABLE_RETRANSLATE
    if (env->se_current_tb->icount == 1) {
        return;
    }

    if (cpu_restore_state(env->se_current_tb, env, env->mem_io_pc)) {
        abort();
    }

    libcpu_log("Aborting and retranslating at eip=%#lx\n", (uint64_t) env->eip);

    env->translate_single_instruction = 1;
    env->exception_index = -1;
    tb_phys_invalidate(env->se_current_tb, -1);
    cpu_loop_exit(env);
#endif
}

uint64_t s2e_kvm_mmio_read(target_phys_addr_t addr, unsigned size) {
    auto dev_result = g_s2e_kvm->vm()->dev_mgr().mmio_read(addr, size);
    if (dev_result) {
        return *dev_result;
    }

    int is_apic_tpr_access = 0;

    ++g_stats.mmio_reads;

    auto cpu = VCPU::current();
    if ((addr >> TARGET_PAGE_BITS) == (cpu->vapic().get_apic_base() >> TARGET_PAGE_BITS)) {
        if ((addr & 0xfff) == 0x80) {
            is_apic_tpr_access = 1;
        }
    }

    if (is_apic_tpr_access) {
        abort_and_retranslate_if_needed();
    }

    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_MMIO;
    g_kvm_vcpu_buffer->mmio.is_write = 0;
    g_kvm_vcpu_buffer->mmio.phys_addr = addr;
    g_kvm_vcpu_buffer->mmio.len = size;

    uint8_t *dataptr = g_kvm_vcpu_buffer->mmio.data;

    coroutine_yield();

    uint64_t ret;
    switch (size) {
        case 1:
            ret = *(uint8_t *) dataptr;
            break;
        case 2:
            ret = *(uint16_t *) dataptr;
            break;
        case 4:
            ret = *(uint32_t *) dataptr;
            break;
        default:
            assert(false && "Can't get here");
    }

    // This is a fix for 32-bits guests that access apic directly
    // and don't use cr8. Writing to cr8 clears the low four bits
    // of the TPR, which may confuse the guest.
    // Note that in 64-bit mode, guests should either use cr8 or
    // MMIO, but not both, so we should still be consistent.
    if (is_apic_tpr_access) {
        if (!(env->hflags & HF_LMA_MASK)) {
            auto apic_tpr = cpu->vapic().get_tpr();
            assert((apic_tpr & 0xf0) == (ret & 0xf0));
            ret |= apic_tpr & 0x3;
        }
    }

#ifdef SE_KVM_DEBUG_MMIO
    unsigned print_addr = 0;
#ifdef SE_KVM_DEBUG_APIC
    if (addr >= 0xf0000000)
        print_addr = 1;
#endif
    if (print_addr) {
        DPRINTF("mmior%d[%" PRIx64 "]=%" PRIx64 "\n", size, (uint64_t) addr, ret);
    }
#endif
    return ret;
}

void s2e_kvm_mmio_write(target_phys_addr_t addr, uint64_t data, unsigned size) {
    int efd = g_s2e_kvm->vm()->lookupIoEventFd(false, addr, data, size);
    if (efd >= 0) {
        signal_ioeventfd(efd);
        return;
    }

    if (g_s2e_kvm->vm()->dev_mgr().mmio_write(addr, data, size)) {
        return;
    }

    ++g_stats.mmio_writes;

    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_MMIO;
    g_kvm_vcpu_buffer->mmio.is_write = 1;
    g_kvm_vcpu_buffer->mmio.phys_addr = addr;
    g_kvm_vcpu_buffer->mmio.len = size;

    uint8_t *dataptr = g_kvm_vcpu_buffer->mmio.data;

#ifdef SE_KVM_DEBUG_MMIO
    unsigned print_addr = 0;
#ifdef SE_KVM_DEBUG_APIC
    if (addr >= 0xf0000000)
        print_addr = 1;
#endif

    if (print_addr) {
        DPRINTF("mmiow%d[%" PRIx64 "]=%" PRIx64 "\n", size, (uint64_t) addr, data);
    }
#endif

    switch (size) {
        case 1:
            *(uint8_t *) dataptr = data;
            break;
        case 2:
            *(uint16_t *) dataptr = data;
            break;
        case 4:
            *(uint32_t *) dataptr = data;
            break;
        default:
            assert(false && "Can't get here");
    }

    auto cpu = VCPU::current();
    bool is_apic_tpr_access = false;
    if ((addr >> TARGET_PAGE_BITS) == (cpu->vapic().get_apic_base() >> TARGET_PAGE_BITS)) {
        if ((addr & 0xfff) == 0x80) {
            abort_and_retranslate_if_needed();
            cpu->vapic().set_tpr((uint8_t) data);
            is_apic_tpr_access = true;
        }
    }

    coroutine_yield();

    // A write to the task priority register may umask hardware interrupts.
    // A real KVM implementation would handle them ASAP on the next instruction.
    // We try to do it as best as we can here by requesting an exit from the CPU loop.
    // Some buggy guests may crash if we exit too late (e.g., winxp).
    // This mechanism is complementary to s2e_kvm_request_exit().
    if (is_apic_tpr_access) {
        cpu_exit(env);
    }
}

uint64_t s2e_kvm_ioport_read(pio_addr_t addr, unsigned size) {
    ++g_stats.io_reads;

    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IO;
    g_kvm_vcpu_buffer->io.direction = KVM_EXIT_IO_IN;
    g_kvm_vcpu_buffer->io.size = size;
    g_kvm_vcpu_buffer->io.port = addr;
    g_kvm_vcpu_buffer->io.count = 1;

    unsigned offs = sizeof(struct kvm_run);
    uint8_t *dataptr = (uint8_t *) g_kvm_vcpu_buffer;
    dataptr += offs;

    g_kvm_vcpu_buffer->io.data_offset = offs;

    coroutine_yield();

    uint64_t ret;
    switch (size) {
        case 1:
            ret = *(uint8_t *) dataptr;
            break;
        case 2:
            ret = *(uint16_t *) dataptr;
            break;
        case 4:
            ret = *(uint32_t *) dataptr;
            break;
        default:
            assert(false && "Can't get here");
    }

#ifdef SE_KVM_DEBUG_IO
    DPRINTF("ior%d[%#x]=0x%" PRIx64 "\n", size, addr, ret);
#endif

    return ret;
}

void s2e_kvm_ioport_write(pio_addr_t addr, uint64_t data, unsigned size) {
    int efd = g_s2e_kvm->vm()->lookupIoEventFd(true, addr, data, size);
    if (efd >= 0) {
        signal_ioeventfd(efd);
        return;
    }

    ++g_stats.io_writes;

    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IO;
    g_kvm_vcpu_buffer->io.direction = KVM_EXIT_IO_OUT;
    g_kvm_vcpu_buffer->io.size = size;
    g_kvm_vcpu_buffer->io.port = addr;
    g_kvm_vcpu_buffer->io.count = 1;

    unsigned offs = sizeof(struct kvm_run);
    uint8_t *dataptr = (uint8_t *) g_kvm_vcpu_buffer;
    dataptr += offs;

    g_kvm_vcpu_buffer->io.data_offset = offs;

    switch (size) {
        case 1:
            *(uint8_t *) dataptr = data;
            break;
        case 2:
            *(uint16_t *) dataptr = data;
            break;
        case 4:
            *(uint32_t *) dataptr = data;
            break;
        default:
            assert(false && "Can't get here");
    }

#ifdef SE_KVM_DEBUG_IO
    DPRINTF("iow%d[%#x]=0x%" PRIx64 "\n", size, addr, data);
#endif

    coroutine_yield();
}

static uint64_t s2e_apic_get_base(CPUX86State *env) {
    auto vcpu = VCPU::current();
    return vcpu->vapic().get_apic_base();
}

static void s2e_apic_set_base(CPUX86State *env, uint64_t new_base) {
    auto vcpu = VCPU::current();
    vcpu->vapic().set_apic_base(new_base);
}

static uint64_t s2e_apic_get_tpr(CPUX86State *env) {
    auto vcpu = VCPU::current();
    return vcpu->vapic().get_tpr();
}

static void s2e_apic_set_tpr(CPUX86State *env, uint64_t new_tpr) {
    auto vcpu = VCPU::current();
    vcpu->vapic().set_tpr(new_tpr);
}

struct cpu_io_funcs_t g_io = {
    .io_read = s2e_kvm_ioport_read,
    .io_write = s2e_kvm_ioport_write,
    .mmio_read = s2e_kvm_mmio_read,
    .mmio_write = s2e_kvm_mmio_write,
    .lapic_get_base = s2e_apic_get_base,
    .lapic_set_base = s2e_apic_set_base,
    .lapic_get_tpr = s2e_apic_get_tpr,
    .lapic_set_tpr = s2e_apic_set_tpr,
};
} // namespace kvm
} // namespace s2e
