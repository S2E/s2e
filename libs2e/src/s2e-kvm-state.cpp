///
/// Copyright (C) 2015-2019, Cyberhaven
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
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cpu/kvm.h>

#include <cpu/se_libcpu.h>
#include <timer.h>

#include "s2e-kvm-vcpu.h"

#define WR_cpu(cpu, reg, value) \
    g_sqi.regs.write_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(target_ulong))
#define RR_cpu(cpu, reg, value) \
    g_sqi.regs.read_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(target_ulong))

extern "C" {
// XXX: fix this declaration
void helper_wrmsr_v(target_ulong index, uint64_t val);
uint64_t helper_rdmsr_v(uint64_t index);
}

namespace s2e {
namespace kvm {

int VCPU::setRegisters(kvm_regs *regs) {
#ifdef CONFIG_SYMBEX
    WR_cpu(m_env, regs[R_EAX], regs->rax);
    WR_cpu(m_env, regs[R_EBX], regs->rbx);
    WR_cpu(m_env, regs[R_ECX], regs->rcx);
    WR_cpu(m_env, regs[R_EDX], regs->rdx);
    WR_cpu(m_env, regs[R_ESI], regs->rsi);
    WR_cpu(m_env, regs[R_EDI], regs->rdi);
    WR_cpu(m_env, regs[R_ESP], regs->rsp);
    WR_cpu(m_env, regs[R_EBP], regs->rbp);

#ifdef TARGET_X86_64
    WR_cpu(m_env, regs[8], regs->r8);
    WR_cpu(m_env, regs[9], regs->r9);
    WR_cpu(m_env, regs[10], regs->r10);
    WR_cpu(m_env, regs[11], regs->r11);
    WR_cpu(m_env, regs[12], regs->r12);
    WR_cpu(m_env, regs[13], regs->r13);
    WR_cpu(m_env, regs[14], regs->r14);
    WR_cpu(m_env, regs[15], regs->r15);
#endif
#else
    m_env->regs[R_EAX] = regs->rax;
    m_env->regs[R_EBX] = regs->rbx;
    m_env->regs[R_ECX] = regs->rcx;
    m_env->regs[R_EDX] = regs->rdx;
    m_env->regs[R_ESI] = regs->rsi;
    m_env->regs[R_EDI] = regs->rdi;
    m_env->regs[R_ESP] = regs->rsp;
    m_env->regs[R_EBP] = regs->rbp;

#ifdef TARGET_X86_64
    m_env->regs[8] = regs->r8;
    m_env->regs[9] = regs->r9;
    m_env->regs[10] = regs->r10;
    m_env->regs[11] = regs->r11;
    m_env->regs[12] = regs->r12;
    m_env->regs[13] = regs->r13;
    m_env->regs[14] = regs->r14;
    m_env->regs[15] = regs->r15;
#endif
#endif

    if (regs->rip != m_env->eip) {
        if (m_handlingKvmCallback || !m_cpuStateIsPrecise) {
            // We don't support this at all, it's better to crash than to risk
            // guest corruption.
            abort();
        }
    }

    m_env->eip = regs->rip;

    if (m_handlingKvmCallback) {
        fprintf(stderr, "warning: kvm setting cpu state while handling io\n");
        // TODO: try to set the system part of the flags register.
        // It should be OK to skip these because the KVM client usually writes
        // back the value it has just read when KVM_RUN exits. That value
        // is already stored in the CPU state of the symbex engine.
        assert(regs->rflags == m_env->mflags);
    } else {
        cpu_set_eflags(m_env, regs->rflags);
    }

    return 0;
}

int VCPU::setFPU(kvm_fpu *fpu) {
    m_env->fpstt = (fpu->fsw >> 11) & 7;
    m_env->fpus = fpu->fsw;
    m_env->fpuc = fpu->fcw;
    m_env->fpop = fpu->last_opcode;
    m_env->fpip = fpu->last_ip;
    m_env->fpdp = fpu->last_dp;
    for (unsigned i = 0; i < 8; ++i) {
        m_env->fptags[i] = !((fpu->ftwx >> i) & 1);
    }
    memcpy(m_env->fpregs, fpu->fpr, sizeof m_env->fpregs);
    memcpy(m_env->xmm_regs, fpu->xmm, sizeof m_env->xmm_regs);
    m_env->mxcsr = fpu->mxcsr;
    return 0;
}

void VCPU::setCpuSegment(SegmentCache *libcpu_seg, const kvm_segment *kvm_seg) {
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

int VCPU::setSystemRegisters(kvm_sregs *sregs) {
    // XXX: what about the interrupt bitmap?
    setCpuSegment(&m_env->segs[R_CS], &sregs->cs);
    setCpuSegment(&m_env->segs[R_DS], &sregs->ds);
    setCpuSegment(&m_env->segs[R_ES], &sregs->es);
    setCpuSegment(&m_env->segs[R_FS], &sregs->fs);
    setCpuSegment(&m_env->segs[R_GS], &sregs->gs);
    setCpuSegment(&m_env->segs[R_SS], &sregs->ss);

    setCpuSegment(&m_env->tr, &sregs->tr);
    setCpuSegment(&m_env->ldt, &sregs->ldt);

    m_env->idt.limit = sregs->idt.limit;
    m_env->idt.base = sregs->idt.base;
    m_env->gdt.limit = sregs->gdt.limit;
    m_env->gdt.base = sregs->gdt.base;

    m_env->cr[0] = sregs->cr0;
    m_env->cr[2] = sregs->cr2;
    m_env->cr[3] = sregs->cr3;
    m_env->cr[4] = sregs->cr4;
    m_env->v_tpr = sregs->cr8;
    m_env->v_apic_tpr = sregs->cr8 << 4;

    if (sregs->apic_base) {
        m_env->v_apic_base = sregs->apic_base;
    }

    m_env->efer = sregs->efer;
    m_env->hflags = cpu_compute_hflags(m_env);

    return 0;
}

int VCPU::setMSRs(kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        helper_wrmsr_v(msrs->entries[i].index, msrs->entries[i].data);
    }
    return msrs->nmsrs;
}

int VCPU::setMPState(kvm_mp_state *mp) {
    /* Only needed when using an irq chip */
    return 0;
}

int VCPU::getRegisters(kvm_regs *regs) {
    if (!m_cpuStateIsPrecise) {
        // Probably OK to let execution continue
        fprintf(stderr, "Getting register state in the middle of a translation block, eip/flags may be imprecise\n");
    }

#ifdef CONFIG_SYMBEX
    RR_cpu(m_env, regs[R_EAX], regs->rax);
    RR_cpu(m_env, regs[R_EBX], regs->rbx);
    RR_cpu(m_env, regs[R_ECX], regs->rcx);
    RR_cpu(m_env, regs[R_EDX], regs->rdx);
    RR_cpu(m_env, regs[R_ESI], regs->rsi);
    RR_cpu(m_env, regs[R_EDI], regs->rdi);
    RR_cpu(m_env, regs[R_ESP], regs->rsp);
    RR_cpu(m_env, regs[R_EBP], regs->rbp);

#ifdef TARGET_X86_64
    RR_cpu(m_env, regs[8], regs->r8);
    RR_cpu(m_env, regs[9], regs->r9);
    RR_cpu(m_env, regs[10], regs->r10);
    RR_cpu(m_env, regs[11], regs->r11);
    RR_cpu(m_env, regs[12], regs->r12);
    RR_cpu(m_env, regs[13], regs->r13);
    RR_cpu(m_env, regs[14], regs->r14);
    RR_cpu(m_env, regs[15], regs->r15);
#endif
#else
    regs->rax = m_env->regs[R_EAX];
    regs->rbx = m_env->regs[R_EBX];
    regs->rcx = m_env->regs[R_ECX];
    regs->rdx = m_env->regs[R_EDX];
    regs->rsi = m_env->regs[R_ESI];
    regs->rdi = m_env->regs[R_EDI];
    regs->rsp = m_env->regs[R_ESP];
    regs->rbp = m_env->regs[R_EBP];

#ifdef TARGET_X86_64
    regs->r8 = m_env->regs[8];
    regs->r9 = m_env->regs[9];
    regs->r10 = m_env->regs[10];
    regs->r11 = m_env->regs[11];
    regs->r12 = m_env->regs[12];
    regs->r13 = m_env->regs[13];
    regs->r14 = m_env->regs[14];
    regs->r15 = m_env->regs[15];
#endif
#endif

    regs->rip = m_env->eip;

    if (!m_handlingKvmCallback) {
        regs->rflags = cpu_get_eflags(m_env);
    } else {
        fprintf(stderr, "warning: kvm asking cpu state while handling io\n");
        // We must at least give the system flags to the KVM client, which
        // may use them to compute the segment registers.
        regs->rflags = m_env->mflags;
    }

    return 0;
}

int VCPU::getFPU(kvm_fpu *fpu) {
    int i;

    fpu->fsw = m_env->fpus & ~(7 << 11);
    fpu->fsw |= (m_env->fpstt & 7) << 11;
    fpu->fcw = m_env->fpuc;
    fpu->last_opcode = m_env->fpop;
    fpu->last_ip = m_env->fpip;
    fpu->last_dp = m_env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu->ftwx |= (!m_env->fptags[i]) << i;
    }
    memcpy(fpu->fpr, m_env->fpregs, sizeof m_env->fpregs);
    memcpy(fpu->xmm, m_env->xmm_regs, sizeof m_env->xmm_regs);
    fpu->mxcsr = m_env->mxcsr;

    return 0;
}

void VCPU::getCpuSegment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
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

void VCPU::get8086Segment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
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

int VCPU::getSystemRegisters(kvm_sregs *sregs) {
    // XXX: what about the interrupt bitmap?

    if (m_env->mflags & VM_MASK) {
        get8086Segment(&sregs->cs, &m_env->segs[R_CS]);
        get8086Segment(&sregs->ds, &m_env->segs[R_DS]);
        get8086Segment(&sregs->es, &m_env->segs[R_ES]);
        get8086Segment(&sregs->fs, &m_env->segs[R_FS]);
        get8086Segment(&sregs->gs, &m_env->segs[R_GS]);
        get8086Segment(&sregs->ss, &m_env->segs[R_SS]);
    } else {
        getCpuSegment(&sregs->cs, &m_env->segs[R_CS]);
        getCpuSegment(&sregs->ds, &m_env->segs[R_DS]);
        getCpuSegment(&sregs->es, &m_env->segs[R_ES]);
        getCpuSegment(&sregs->fs, &m_env->segs[R_FS]);
        getCpuSegment(&sregs->gs, &m_env->segs[R_GS]);
        getCpuSegment(&sregs->ss, &m_env->segs[R_SS]);
    }

    getCpuSegment(&sregs->tr, &m_env->tr);
    getCpuSegment(&sregs->ldt, &m_env->ldt);

    sregs->idt.limit = m_env->idt.limit;
    sregs->idt.base = m_env->idt.base;
    memset(sregs->idt.padding, 0, sizeof sregs->idt.padding);
    sregs->gdt.limit = m_env->gdt.limit;
    sregs->gdt.base = m_env->gdt.base;
    memset(sregs->gdt.padding, 0, sizeof sregs->gdt.padding);

    sregs->cr0 = m_env->cr[0];
    sregs->cr2 = m_env->cr[2];
    sregs->cr3 = m_env->cr[3];
    sregs->cr4 = m_env->cr[4];
    sregs->cr8 = m_env->v_tpr;

    sregs->apic_base = m_env->v_apic_base;
    sregs->cr8 = m_env->v_tpr;

    sregs->efer = m_env->efer;
    return 0;
}

int VCPU::getMSRs(kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        msrs->entries[i].data = helper_rdmsr_v(msrs->entries[i].index);
    }
    return msrs->nmsrs;
}

int VCPU::getMPState(kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}
} // namespace kvm
} // namespace s2e
