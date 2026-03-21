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

#ifdef CONFIG_SYMBEX
#define WR_cpu(cpu, reg, value) \
    g_sqi.regs.write_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(CPUX86State::reg))
#define RR_cpu(cpu, reg, value) \
    g_sqi.regs.read_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(CPUX86State::reg))
#else
#define WR_cpu(cpu, reg, value) (cpu)->reg = value
#define RR_cpu(cpu, reg, value) value = (cpu)->reg
#endif

extern "C" {
// XXX: fix this declaration
void helper_wrmsr_v(target_ulong index, uint64_t val);
uint64_t helper_rdmsr_v(uint64_t index);
}

namespace s2e {
namespace kvm {

// MPX (Memory Protection Extensions) register types
typedef struct BNDReg {
    uint64_t lower;
    uint64_t upper;
} BNDReg;

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t status;
} BNDCSReg;

// AVX-512 constants
#define NB_OPMASK_REGS 8

typedef union X86LegacyXSaveArea {
    struct {
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t reserved;
        uint16_t fpop;
        uint64_t fpip;
        uint64_t fpdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        FPReg fpregs[8];
        uint8_t xmm_regs[16][16];
    };
    uint8_t data[512];
} X86LegacyXSaveArea;

typedef struct X86XSaveHeader {
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t reserve0;
    uint8_t reserved[40];
} X86XSaveHeader;

/* Ext. save area 2: AVX State */
typedef struct XSaveAVX {
    uint8_t ymmh[16][16];
} XSaveAVX;

/* Ext. save area 3: BNDREG */
typedef struct XSaveBNDREG {
    BNDReg bnd_regs[4];
} XSaveBNDREG;

/* Ext. save area 4: BNDCSR */
typedef union XSaveBNDCSR {
    BNDCSReg bndcsr;
    uint8_t data[64];
} XSaveBNDCSR;

/* Ext. save area 5: Opmask */
typedef struct XSaveOpmask {
    uint64_t opmask_regs[NB_OPMASK_REGS];
} XSaveOpmask;

/* Ext. save area 6: ZMM_Hi256 */
typedef struct XSaveZMM_Hi256 {
    uint8_t zmm_hi256[16][32];
} XSaveZMM_Hi256;

/* Ext. save area 7: Hi16_ZMM */
typedef struct XSaveHi16_ZMM {
    uint8_t hi16_zmm[16][64];
} XSaveHi16_ZMM;

/* Ext. save area 9: PKRU state */
typedef struct XSavePKRU {
    uint32_t pkru;
    uint32_t padding;
} XSavePKRU;

typedef struct X86XSaveArea {
    X86LegacyXSaveArea legacy;
    X86XSaveHeader header;

    /* Extended save areas: */

    /* AVX State: */
    XSaveAVX avx_state;
    uint8_t padding[960 - 576 - sizeof(XSaveAVX)];
    /* MPX State: */
    XSaveBNDREG bndreg_state;
    XSaveBNDCSR bndcsr_state;
    /* AVX-512 State: */
    XSaveOpmask opmask_state;
    XSaveZMM_Hi256 zmm_hi256_state;
    XSaveHi16_ZMM hi16_zmm_state;
    /* PKRU State: */
    XSavePKRU pkru_state;
} X86XSaveArea;

int VCPU::setRegisters(kvm_regs *regs) {
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
    unsigned int fpstt = (fpu->fsw >> 11) & 7;
    WR_cpu(m_env, fpstt, fpstt);
    WR_cpu(m_env, fpus, fpu->fsw);
    WR_cpu(m_env, fpuc, fpu->fcw);
    WR_cpu(m_env, fpop, fpu->last_opcode);
    WR_cpu(m_env, fpip, fpu->last_ip);
    WR_cpu(m_env, fpdp, fpu->last_dp);
    for (unsigned i = 0; i < 8; ++i) {
        uint8_t tag = !((fpu->ftwx >> i) & 1);
        WR_cpu(m_env, fptags[i], tag);
    }
    for (unsigned i = 0; i < 8; ++i) {
        FPReg reg;
        memcpy(&reg, fpu->fpr[i], sizeof(reg));
        WR_cpu(m_env, fpregs[i], reg);
    }
    for (unsigned i = 0; i < CPU_NB_REGS; ++i) {
        XMMReg reg;
        memcpy(&reg, fpu->xmm[i], sizeof(reg));
        WR_cpu(m_env, xmm_regs[i], reg);
    }
    WR_cpu(m_env, mxcsr, fpu->mxcsr);
    return 0;
}

int VCPU::setXSAVE(kvm_xsave *xsave) {
    // XSAVE state layout (total 4096 bytes):
    // Offset   0-511: Legacy region (FXSAVE compatible)
    // Offset 512-575: XSAVE header
    // Offset 576+   : Extended state components (AVX, MPX, AVX-512, etc.)
    //
    // This implementation is based on QEMU 10's x86_cpu_xsave_all_areas
    // but adapted for loading state (reverse operation).

    X86XSaveArea *xsave_area = (X86XSaveArea *) xsave->region;
    uint16_t swd, twd;
    int i;

    // Restore FPU control and status words
    WR_cpu(m_env, fpuc, xsave_area->legacy.fcw);

    swd = xsave_area->legacy.fsw;
    unsigned int fpstt = (swd >> 11) & 7;
    WR_cpu(m_env, fpstt, fpstt);

    WR_cpu(m_env, fpus, swd);

    // Restore FPU tag word (convert from abridged format)
    twd = xsave_area->legacy.ftw;
    for (i = 0; i < 8; ++i) {
        uint8_t tag = !(twd & (1 << i));
        WR_cpu(m_env, fptags[i], tag);
    }

    // Restore FPU instruction pointer, data pointer, and last opcode
    WR_cpu(m_env, fpop, xsave_area->legacy.fpop);
    WR_cpu(m_env, fpip, xsave_area->legacy.fpip);
    WR_cpu(m_env, fpdp, xsave_area->legacy.fpdp);

    // Restore FPU registers (ST0-ST7)
    for (i = 0; i < 8; ++i) {
        WR_cpu(m_env, fpregs[i], xsave_area->legacy.fpregs[i]);
    }

    // Restore MXCSR
    WR_cpu(m_env, mxcsr, xsave_area->legacy.mxcsr);

    for (i = 0; i < CPU_NB_REGS; i++) {
        // Restore XMM (low 128 bits)
        XMMReg xmm_reg;
        memcpy(&xmm_reg, xsave_area->legacy.xmm_regs[i], sizeof(xmm_reg));
        WR_cpu(m_env, xmm_regs[i], xmm_reg);
    }

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
    uint16_t fpus;
    RR_cpu(m_env, fpus, fpus);
    unsigned int fpstt;
    RR_cpu(m_env, fpstt, fpstt);
    fpu->fsw = fpus & ~(7 << 11);
    fpu->fsw |= (fpstt & 7) << 11;

    RR_cpu(m_env, fpuc, fpu->fcw);
    RR_cpu(m_env, fpop, fpu->last_opcode);
    RR_cpu(m_env, fpip, fpu->last_ip);
    RR_cpu(m_env, fpdp, fpu->last_dp);
    for (int i = 0; i < 8; ++i) {
        uint8_t tag;
        RR_cpu(m_env, fptags[i], tag);
        fpu->ftwx |= (!tag) << i;
    }
    for (int i = 0; i < 8; ++i) {
        FPReg reg;
        RR_cpu(m_env, fpregs[i], reg);
        memcpy(fpu->fpr[i], &reg, sizeof(reg));
    }
    for (int i = 0; i < CPU_NB_REGS; ++i) {
        XMMReg reg;
        RR_cpu(m_env, xmm_regs[i], reg);
        memcpy(fpu->xmm[i], &reg, sizeof(reg));
    }
    RR_cpu(m_env, mxcsr, fpu->mxcsr);

    return 0;
}

int VCPU::getXSAVE(kvm_xsave *xsave) {
    X86XSaveArea *xsave_area = (X86XSaveArea *) xsave->region;
    int i;

    // Zero out the entire region first
    memset(xsave->region, 0, sizeof(xsave->region));

    // Reconstruct FSW from fpus and fpstt
    uint16_t fpus;
    RR_cpu(m_env, fpus, fpus);
    unsigned int fpstt;
    RR_cpu(m_env, fpstt, fpstt);
    xsave_area->legacy.fsw = (fpus & ~(7 << 11)) | ((fpstt & 7) << 11);

    // FPU control word
    RR_cpu(m_env, fpuc, xsave_area->legacy.fcw);

    // FPU tag word (convert from internal format to abridged)
    uint8_t ftw = 0;
    for (i = 0; i < 8; ++i) {
        uint8_t tag;
        RR_cpu(m_env, fptags[i], tag);
        ftw |= (!tag) << i;
    }
    xsave_area->legacy.ftw = ftw;

    // FPU instruction pointer, data pointer, and last opcode
    RR_cpu(m_env, fpop, xsave_area->legacy.fpop);
    RR_cpu(m_env, fpip, xsave_area->legacy.fpip);
    RR_cpu(m_env, fpdp, xsave_area->legacy.fpdp);

    // FPU registers (ST0-ST7)
    for (i = 0; i < 8; ++i) {
        RR_cpu(m_env, fpregs[i], xsave_area->legacy.fpregs[i]);
    }

    // MXCSR
    RR_cpu(m_env, mxcsr, xsave_area->legacy.mxcsr);

    for (i = 0; i < CPU_NB_REGS; i++) {
        // XMM (low 128 bits) in legacy area
        XMMReg xmm_reg;
        RR_cpu(m_env, xmm_regs[i], xmm_reg);
        memcpy(xsave_area->legacy.xmm_regs[i], &xmm_reg, sizeof(xmm_reg));
    }

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

int VCPU::setDebugRegs(kvm_debugregs *dregs) {
    for (int i = 0; i < 4; ++i) {
        m_env->dr[i] = dregs->db[i];
    }
    m_env->dr[6] = dregs->dr6;
    m_env->dr[7] = dregs->dr7;
    return 0;
}

int VCPU::getDebugRegs(kvm_debugregs *dregs) {
    memset(dregs, 0, sizeof(*dregs));
    for (int i = 0; i < 4; ++i) {
        dregs->db[i] = m_env->dr[i];
    }
    dregs->dr6 = m_env->dr[6];
    dregs->dr7 = m_env->dr[7];
    return 0;
}

int VCPU::getMPState(kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}
} // namespace kvm
} // namespace s2e
