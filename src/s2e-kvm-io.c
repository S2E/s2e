///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <coroutine.h>
#include <cpu/ioport.h>
#include <cpu/kvm.h>
#include <cpu/memory.h>
#include <inttypes.h>

#include <cpu/i386/cpu.h>
#include "s2e-kvm-interface.h"

extern CPUX86State *env;

uint64_t s2e_kvm_mmio_read(target_phys_addr_t addr, unsigned size) {
    ++g_stats.mmio_reads;

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
    // and don't use cr8. Writing to cr8 clears the low for bits
    // of the TPR, which may confuse the guest.
    // Note that in 64-bit mode, guests should wither use cr8 or
    // MMIO, but not both, so we should still be consistent.
    if ((addr >> TARGET_PAGE_BITS) == (env->v_apic_base >> TARGET_PAGE_BITS)) {
        if ((addr & 0xfff) == 0x80) {
            if (!(env->hflags & HF_LMA_MASK)) {
                assert((env->v_apic_tpr & 0xf0) == (ret & 0xf0));
                ret |= env->v_apic_tpr & 0x3;
            }
        }
    }

#ifdef SE_KVM_DEBUG_MMIO
    unsigned print_addr = 0;
#ifdef SE_KVM_DEBUG_APIC
    if (addr >= 0xf0000000)
        print_addr = 1;
#endif
    if (print_addr) {
        printf("mmior%d[%" PRIx64 "]=%" PRIx64 "\n", size, (uint64_t) addr, ret);
        // printf("env->mflags=%x hflags=%x hflags2=%x\n",
        //       env->mflags, env->hflags, env->hflags2);
    }
#endif
    return ret;
}

void s2e_kvm_mmio_write(target_phys_addr_t addr, uint64_t data, unsigned size) {
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
        printf("mmiow%d[%" PRIx64 "]=%" PRIx64 "\n", size, (uint64_t) addr, data);
        // printf("env->mflags=%x hflags=%x hflags2=%x\n",
        //       env->mflags, env->hflags, env->hflags2);
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

    if ((addr >> TARGET_PAGE_BITS) == (env->v_apic_base >> TARGET_PAGE_BITS)) {
        if ((addr & 0xfff) == 0x80) {
            env->v_apic_tpr = (uint8_t) data;
            env->v_tpr = env->v_apic_tpr >> 4;
        }
    }

    coroutine_yield();
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
    printf("ior%d[%x]=%" PRIx64 "\n", size, addr, ret);
// printf("env->mflags=%x hflags=%x hflags2=%x\n",
//       env->mflags, env->hflags, env->hflags2);
#endif

    return ret;
}

void s2e_kvm_ioport_write(pio_addr_t addr, uint64_t data, unsigned size) {
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
    printf("iow%d[%x]=%" PRIx64 "\n", size, addr, data);
// printf("env->mflags=%x hflags=%x hflags2=%x\n",
//       env->mflags, env->hflags, env->hflags2);
#endif

    coroutine_yield();
}

struct cpu_io_funcs_t g_io = {
    .io_read = s2e_kvm_ioport_read,
    .io_write = s2e_kvm_ioport_write,
    .mmio_read = s2e_kvm_mmio_read,
    .mmio_write = s2e_kvm_mmio_write,
};
