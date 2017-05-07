///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIT(n) (1 << (n))
#include <cpu/kvm.h>

#include <cpu/i386/cpu.h>
#include <timer.h>
#include "s2e-kvm-interface.h"

extern CPUX86State *env;

// clang-format off
static uint32_t s_msr_list [] = {
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_APICBASE,
    MSR_EFER,
    MSR_STAR,
    MSR_PAT,
    MSR_VM_HSAVE_PA,
    #ifdef TARGET_X86_64
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_FMASK,
    MSR_FSBASE,
    MSR_GSBASE,
    MSR_KERNELGSBASE,
    #endif
    MSR_MTRRphysBase(0),
    MSR_MTRRphysBase(1),
    MSR_MTRRphysBase(2),
    MSR_MTRRphysBase(3),
    MSR_MTRRphysBase(4),
    MSR_MTRRphysBase(5),
    MSR_MTRRphysBase(6),
    MSR_MTRRphysBase(7),
    MSR_MTRRphysMask(0),
    MSR_MTRRphysMask(1),
    MSR_MTRRphysMask(2),
    MSR_MTRRphysMask(3),
    MSR_MTRRphysMask(4),
    MSR_MTRRphysMask(5),
    MSR_MTRRphysMask(6),
    MSR_MTRRphysMask(7),
    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,
    MSR_MCG_STATUS,
    MSR_MCG_CTL,
    MSR_TSC_AUX,
    MSR_IA32_MISC_ENABLE,
    MSR_MC0_CTL,
    MSR_MC0_STATUS,
    MSR_MC0_ADDR,
    MSR_MC0_MISC
};

/* Array of valid (function, index) entries */
static uint32_t s_cpuid_entries[][2] = {
    {0, -1},
    {1, -1},
    {2, -1},
    {4, 0},
    {4, 1},
    {4, 2},
    {4, 3},
    {5, -1},
    {6, -1},
    {7, -1},
    {9, -1},
    {0xa, -1},
    {0xd, -1},
    {0x80000000, -1},
    {0x80000001, -1},
    {0x80000002, -1},
    {0x80000003, -1},
    {0x80000004, -1},
    {0x80000005, -1},
    {0x80000006, -1},
    {0x80000008, -1},
    {0x8000000a, -1},
    {0xc0000000, -1},
    {0xc0000001, -1},
    {0xc0000002, -1},
    {0xc0000003, -1},
    {0xc0000004, -1}
};
// clang-format on

int s2e_kvm_get_msr_index_list(int kvm_fd, struct kvm_msr_list *list) {
    if (list->nmsrs == 0) {
        list->nmsrs = sizeof(s_msr_list) / sizeof(s_msr_list[0]);
    } else {
        for (int i = 0; i < list->nmsrs; ++i) {
            list->indices[i] = s_msr_list[i];
        }
    }

    return 0;
}

#ifdef SE_KVM_DEBUG_CPUID
static void print_cpuid2(struct kvm_cpuid_entry2 *e) {
    printf("cpuid function=%#010" PRIx32 " index=%#010" PRIx32 " flags=%#010" PRIx32 " eax=%#010" PRIx32
           " ebx=%#010" PRIx32 " ecx=%#010" PRIx32 " edx=%#010" PRIx32 "\n",
           e->function, e->index, e->flags, e->eax, e->ebx, e->ecx, e->edx);
}
#endif

int s2e_kvm_get_supported_cpuid(int kvm_fd, struct kvm_cpuid2 *cpuid) {
#ifdef SE_KVM_DEBUG_CPUID
    printf("%s\n", __FUNCTION__);
#endif

    unsigned int nentries = sizeof(s_cpuid_entries) / sizeof(s_cpuid_entries[0]);
    if (cpuid->nent < nentries) {
        errno = E2BIG;
        return -1;
    } else if (cpuid->nent >= nentries) {
        cpuid->nent = nentries;
        // errno = ENOMEM;
        // return -1;
    }

    for (unsigned i = 0; i < nentries; ++i) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        cpu_x86_cpuid(env, s_cpuid_entries[i][0], s_cpuid_entries[i][1], &e->eax, &e->ebx, &e->ecx, &e->edx);

        e->flags = 0;
        e->index = 0;
        if (s_cpuid_entries[i][1] != -1) {
            e->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            e->index = s_cpuid_entries[i][1];
        }
        e->function = s_cpuid_entries[i][0];

#ifdef SE_KVM_DEBUG_CPUID
        print_cpuid2(e);
#endif
    }

    return 0;
}

int s2e_kvm_vcpu_set_cpuid2(int vcpu_fd, struct kvm_cpuid2 *cpuid) {
/**
 * QEMU insists on using host cpuid flags when running in KVM mode.
 * We want to use those set in DBT mode instead.
 * TODO: for now, we have no way to configure custom flags.
 * Snapshots will not work if using anything other that defaults.
 */

/// This check ensures that users don't mistakenly use the wrong build of libs2e.
#if defined(TARGET_X86_64)
    if (cpuid->nent == 15) {
        fprintf(stderr, "libs2e for 64-bit guests is used but the KVM client requested 32-bit features\n");
        exit(1);
    }
#elif defined(TARGET_I386)
    if (cpuid->nent == 21) {
        fprintf(stderr, "libs2e for 32-bit guests is used but the KVM client requested 64-bit features\n");
        exit(1);
    }
#else
#error unknown architecture
#endif

    return 0;
}

int s2e_kvm_vcpu_set_regs(int vcpu_fd, struct kvm_regs *regs) {
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_ESP] = regs->rsp;
    env->regs[R_EBP] = regs->rbp;

#ifdef TARGET_X86_64
    env->regs[8] = regs->r8;
    env->regs[9] = regs->r9;
    env->regs[10] = regs->r10;
    env->regs[11] = regs->r11;
    env->regs[12] = regs->r12;
    env->regs[13] = regs->r13;
    env->regs[14] = regs->r14;
    env->regs[15] = regs->r15;
#endif

    env->eip = regs->rip;

    if (g_handling_kvm_cb) {
        fprintf(stderr, "warning: kvm asking cpu state while handling io\n");
    } else {
        cpu_set_eflags(env, regs->rflags);
    }

    return 0;
}

int s2e_kvm_vcpu_set_fpu(int vcpu_fd, struct kvm_fpu *fpu) {
    env->fpstt = (fpu->fsw >> 11) & 7;
    env->fpus = fpu->fsw;
    env->fpuc = fpu->fcw;
    env->fpop = fpu->last_opcode;
    env->fpip = fpu->last_ip;
    env->fpdp = fpu->last_dp;
    for (unsigned i = 0; i < 8; ++i) {
        env->fptags[i] = !((fpu->ftwx >> i) & 1);
    }
    memcpy(env->fpregs, fpu->fpr, sizeof env->fpregs);
    memcpy(env->xmm_regs, fpu->xmm, sizeof env->xmm_regs);
    env->mxcsr = fpu->mxcsr;
    return 0;
}

static void set_libcpu_segment(SegmentCache *libcpu_seg, const struct kvm_segment *kvm_seg) {
    libcpu_seg->selector = kvm_seg->selector;
    libcpu_seg->base = kvm_seg->base;
    libcpu_seg->limit = kvm_seg->limit;
    libcpu_seg->flags = (kvm_seg->type << DESC_TYPE_SHIFT) | (kvm_seg->present * DESC_P_MASK) |
                        (kvm_seg->dpl << DESC_DPL_SHIFT) | (kvm_seg->db << DESC_B_SHIFT) | (kvm_seg->s * DESC_S_MASK) |
                        (kvm_seg->l << DESC_L_SHIFT) | (kvm_seg->g * DESC_G_MASK) | (kvm_seg->avl * DESC_AVL_MASK);

    if (libcpu_seg->flags & DESC_G_MASK) {
        libcpu_seg->flags |= (libcpu_seg->limit >> 12) & 0x000f0000;
    }

    libcpu_seg->flags |= libcpu_seg->base & 0xff000000;
    libcpu_seg->flags |= (libcpu_seg->base & 0x00ff0000) >> 16;
}

int s2e_kvm_vcpu_set_sregs(int vcpu_fd, struct kvm_sregs *sregs) {
    // XXX: what about the interrupt bitmap?
    set_libcpu_segment(&env->segs[R_CS], &sregs->cs);
    set_libcpu_segment(&env->segs[R_DS], &sregs->ds);
    set_libcpu_segment(&env->segs[R_ES], &sregs->es);
    set_libcpu_segment(&env->segs[R_FS], &sregs->fs);
    set_libcpu_segment(&env->segs[R_GS], &sregs->gs);
    set_libcpu_segment(&env->segs[R_SS], &sregs->ss);

    set_libcpu_segment(&env->tr, &sregs->tr);
    set_libcpu_segment(&env->ldt, &sregs->ldt);

    env->idt.limit = sregs->idt.limit;
    env->idt.base = sregs->idt.base;
    env->gdt.limit = sregs->gdt.limit;
    env->gdt.base = sregs->gdt.base;

    env->cr[0] = sregs->cr0;
    env->cr[2] = sregs->cr2;
    env->cr[3] = sregs->cr3;
    env->cr[4] = sregs->cr4;
    env->v_tpr = sregs->cr8;
    env->v_apic_tpr = sregs->cr8 << 4;

    if (sregs->apic_base) {
        env->v_apic_base = sregs->apic_base;
    }

    env->efer = sregs->efer;
    env->hflags = cpu_compute_hflags(env);

    return 0;
}

void helper_wrmsr_v(target_ulong index, uint64_t val);
int s2e_kvm_vcpu_set_msrs(int vcpu_fd, struct kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        helper_wrmsr_v(msrs->entries[i].index, msrs->entries[i].data);
    }
    return 0;
}

int s2e_kvm_vcpu_set_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    /* Only needed when using an irq chip */
    return 0;
}

int s2e_kvm_vcpu_get_regs(int vcpu_fd, struct kvm_regs *regs) {
    regs->rax = env->regs[R_EAX];
    regs->rbx = env->regs[R_EBX];
    regs->rcx = env->regs[R_ECX];
    regs->rdx = env->regs[R_EDX];
    regs->rsi = env->regs[R_ESI];
    regs->rdi = env->regs[R_EDI];
    regs->rsp = env->regs[R_ESP];
    regs->rbp = env->regs[R_EBP];

#ifdef TARGET_X86_64
    regs->r8 = env->regs[8];
    regs->r9 = env->regs[9];
    regs->r10 = env->regs[10];
    regs->r11 = env->regs[11];
    regs->r12 = env->regs[12];
    regs->r13 = env->regs[13];
    regs->r14 = env->regs[14];
    regs->r15 = env->regs[15];
#endif

    regs->rip = env->eip;

    if (!g_handling_kvm_cb) {
        regs->rflags = cpu_get_eflags(env);
    } else {
        fprintf(stderr, "warning: kvm asking cpu state while handling io\n");
    }

    return 0;
}

int s2e_kvm_vcpu_get_fpu(int vcpu_fd, struct kvm_fpu *fpu) {
    int i;

    fpu->fsw = env->fpus & ~(7 << 11);
    fpu->fsw |= (env->fpstt & 7) << 11;
    fpu->fcw = env->fpuc;
    fpu->last_opcode = env->fpop;
    fpu->last_ip = env->fpip;
    fpu->last_dp = env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu->ftwx |= (!env->fptags[i]) << i;
    }
    memcpy(fpu->fpr, env->fpregs, sizeof env->fpregs);
    memcpy(fpu->xmm, env->xmm_regs, sizeof env->xmm_regs);
    fpu->mxcsr = env->mxcsr;

    return 0;
}

static void get_libcpu_segment(struct kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
    unsigned flags = libcpu_seg->flags;
    kvm_seg->selector = libcpu_seg->selector;
    kvm_seg->base = libcpu_seg->base;
    kvm_seg->limit = libcpu_seg->limit;
    kvm_seg->type = (flags >> DESC_TYPE_SHIFT) & 15;
    kvm_seg->present = (flags & DESC_P_MASK) != 0;
    kvm_seg->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    kvm_seg->db = (flags >> DESC_B_SHIFT) & 1;
    kvm_seg->s = (flags & DESC_S_MASK) != 0;
    kvm_seg->l = (flags >> DESC_L_SHIFT) & 1;
    kvm_seg->g = (flags & DESC_G_MASK) != 0;
    kvm_seg->avl = (flags & DESC_AVL_MASK) != 0;
    kvm_seg->unusable = 0;
    kvm_seg->padding = 0;
}

static void get_v8086_segment(struct kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
    kvm_seg->selector = libcpu_seg->selector;
    kvm_seg->base = libcpu_seg->base;
    kvm_seg->limit = libcpu_seg->limit;
    kvm_seg->type = 3;
    kvm_seg->present = 1;
    kvm_seg->dpl = 3;
    kvm_seg->db = 0;
    kvm_seg->s = 1;
    kvm_seg->l = 0;
    kvm_seg->g = 0;
    kvm_seg->avl = 0;
    kvm_seg->unusable = 0;
}

int s2e_kvm_vcpu_get_sregs(int vcpu_fd, struct kvm_sregs *sregs) {
    // XXX: what about the interrupt bitmap?

    if (env->mflags & VM_MASK) {
        get_v8086_segment(&sregs->cs, &env->segs[R_CS]);
        get_v8086_segment(&sregs->ds, &env->segs[R_DS]);
        get_v8086_segment(&sregs->es, &env->segs[R_ES]);
        get_v8086_segment(&sregs->fs, &env->segs[R_FS]);
        get_v8086_segment(&sregs->gs, &env->segs[R_GS]);
        get_v8086_segment(&sregs->ss, &env->segs[R_SS]);
    } else {
        get_libcpu_segment(&sregs->cs, &env->segs[R_CS]);
        get_libcpu_segment(&sregs->ds, &env->segs[R_DS]);
        get_libcpu_segment(&sregs->es, &env->segs[R_ES]);
        get_libcpu_segment(&sregs->fs, &env->segs[R_FS]);
        get_libcpu_segment(&sregs->gs, &env->segs[R_GS]);
        get_libcpu_segment(&sregs->ss, &env->segs[R_SS]);
    }

    get_libcpu_segment(&sregs->tr, &env->tr);
    get_libcpu_segment(&sregs->ldt, &env->ldt);

    sregs->idt.limit = env->idt.limit;
    sregs->idt.base = env->idt.base;
    memset(sregs->idt.padding, 0, sizeof sregs->idt.padding);
    sregs->gdt.limit = env->gdt.limit;
    sregs->gdt.base = env->gdt.base;
    memset(sregs->gdt.padding, 0, sizeof sregs->gdt.padding);

    sregs->cr0 = env->cr[0];
    sregs->cr2 = env->cr[2];
    sregs->cr3 = env->cr[3];
    sregs->cr4 = env->cr[4];
    sregs->cr8 = env->v_tpr;

    sregs->apic_base = env->v_apic_base;
    sregs->cr8 = env->v_tpr;

    sregs->efer = env->efer;
    return 0;
}

int s2e_kvm_vcpu_get_msrs(int vcpu_fd, struct kvm_msrs *msrs) {
    uint64_t helper_rdmsr_v(uint64_t index);

    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        msrs->entries[i].data = helper_rdmsr_v(msrs->entries[i].index);
    }
    return msrs->nmsrs;
}

int s2e_kvm_vcpu_get_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}

int s2e_kvm_vm_set_tss_addr(int vm_fd, uint64_t tss_addr) {
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("Setting tss addr %#" PRIx64 " not implemented yet\n", tss_addr);
#endif
    return 0;
}

uint64_t g_clock_start = 0;
uint64_t g_clock_offset = 0;
int s2e_kvm_vm_set_clock(int vm_fd, struct kvm_clock_data *clock) {
    g_clock_start = clock->clock;
    g_clock_offset = cpu_get_real_ticks();
    return 0;
}

int s2e_kvm_vm_get_clock(int vm_fd, struct kvm_clock_data *clock) {
    clock->clock = cpu_get_real_ticks() - g_clock_offset + g_clock_start;
    clock->flags = 0;
    return 0;
}
