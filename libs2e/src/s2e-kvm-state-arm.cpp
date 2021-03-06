///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define BIT(n) (1 << (n))
#include <cpu/kvm.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include <timer.h>

#include "s2e-kvm-vcpu.h"

#define WR_cpu(cpu, reg, value) \
    g_sqi.regs.write_concrete(offsetof(CPUARMState, reg), (uint8_t *) &value, sizeof(target_ulong))
#define RR_cpu(cpu, reg, value) \
    g_sqi.regs.read_concrete(offsetof(CPUARMState, reg), (uint8_t *) &value, sizeof(target_ulong))

namespace s2e {
namespace kvm {

int VCPU::setRegs(kvm_m_regs *regs) {
#ifdef CONFIG_SYMBEX
    WR_cpu(m_env, regs[0], regs->regs[0]);
    WR_cpu(m_env, regs[1], regs->regs[1]);
    WR_cpu(m_env, regs[2], regs->regs[2]);
    WR_cpu(m_env, regs[3], regs->regs[3]);
    WR_cpu(m_env, regs[4], regs->regs[4]);
    WR_cpu(m_env, regs[5], regs->regs[5]);
    WR_cpu(m_env, regs[6], regs->regs[6]);
    WR_cpu(m_env, regs[7], regs->regs[7]);
    WR_cpu(m_env, regs[8], regs->regs[8]);
    WR_cpu(m_env, regs[9], regs->regs[9]);
    WR_cpu(m_env, regs[10], regs->regs[10]);
    WR_cpu(m_env, regs[11], regs->regs[11]);
    WR_cpu(m_env, regs[12], regs->regs[12]);
    WR_cpu(m_env, regs[13], regs->regs[13]);
    WR_cpu(m_env, regs[14], regs->regs[14]);
#else
    m_env->regs[0] = regs->regs[0];
    m_env->regs[1] = regs->regs[1];
    m_env->regs[2] = regs->regs[2];
    m_env->regs[3] = regs->regs[3];
    m_env->regs[4] = regs->regs[4];
    m_env->regs[5] = regs->regs[5];
    m_env->regs[6] = regs->regs[6];
    m_env->regs[7] = regs->regs[7];
    m_env->regs[8] = regs->regs[8];
    m_env->regs[9] = regs->regs[9];
    m_env->regs[10] = regs->regs[10];
    m_env->regs[11] = regs->regs[11];
    m_env->regs[12] = regs->regs[12];
    m_env->regs[13] = regs->regs[13];
    m_env->regs[14] = regs->regs[14];
#endif
    m_env->regs[15] = regs->regs[15];

    return 0;
}

int VCPU::setSRegs(kvm_m_sregs *sregs) {
    // XXX: what about the nvic interrupt controller ?
    m_env->v7m.other_sp = sregs->other_sp;
    m_env->v7m.vecbase = sregs->vecbase;
    m_env->v7m.basepri = sregs->basepri;
    m_env->v7m.control = sregs->control;
    m_env->v7m.current_sp = sregs->current_sp;
    m_env->v7m.exception = sregs->exception;
    m_env->v7m.pending_exception = sregs->pending_exception;
    m_env->thumb = sregs->thumb;
    m_env->nvic = sregs->nvic;
    printf("vecbase=%#x\n", m_env->v7m.vecbase);
    return 0;
}

int VCPU::setOneReg(kvm_one_reg *reg) {

    uint32 *uaddr = (uint32 *) (long) reg->addr;
    // We currently use nothing arch-specific in upper 32 bits
    if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM >> 32)
        return -EINVAL;

    // Register group 16 means we set a core register.
    if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
        return set_core_reg(reg);

    if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_VFP)
        return vfp_set_reg(reg->id, uaddr);

    return (reg->id & KVM_REG_ARM_COPROC_MASK);
}

int VCPU::setMPState(kvm_mp_state *mp) {
    // Only needed when using an irq chip
    return 0;
}

int VCPU::getRegs(kvm_m_regs *regs) {
    if (!m_cpuStateIsPrecise) {
        // Probably OK to let execution continue
        fprintf(stderr, "Getting register state in the middle of a translation block, eip/flags may be imprecise\n");
    }

#ifdef CONFIG_SYMBEX
    RR_cpu(m_env, regs[0], regs->regs[0]);
    RR_cpu(m_env, regs[1], regs->regs[1]);
    RR_cpu(m_env, regs[2], regs->regs[2]);
    RR_cpu(m_env, regs[3], regs->regs[3]);
    RR_cpu(m_env, regs[4], regs->regs[4]);
    RR_cpu(m_env, regs[5], regs->regs[5]);
    RR_cpu(m_env, regs[6], regs->regs[6]);
    RR_cpu(m_env, regs[7], regs->regs[7]);
    RR_cpu(m_env, regs[8], regs->regs[8]);
    RR_cpu(m_env, regs[9], regs->regs[9]);
    RR_cpu(m_env, regs[10], regs->regs[10]);
    RR_cpu(m_env, regs[11], regs->regs[11]);
    RR_cpu(m_env, regs[12], regs->regs[12]);
    RR_cpu(m_env, regs[13], regs->regs[13]);
    RR_cpu(m_env, regs[14], regs->regs[14]);
#else
    regs->regs[0] = m_env->regs[0];
    regs->regs[1] = m_env->regs[1];
    regs->regs[2] = m_env->regs[2];
    regs->regs[3] = m_env->regs[3];
    regs->regs[4] = m_env->regs[4];
    regs->regs[5] = m_env->regs[5];
    regs->regs[6] = m_env->regs[6];
    regs->regs[7] = m_env->regs[7];
    regs->regs[8] = m_env->regs[8];
    regs->regs[9] = m_env->regs[9];
    regs->regs[10] = m_env->regs[10];
    regs->regs[11] = m_env->regs[11];
    regs->regs[12] = m_env->regs[12];
    regs->regs[13] = m_env->regs[13];
    regs->regs[14] = m_env->regs[14];
#endif

    regs->regs[15] = m_env->regs[15];
    return 0;
}

int VCPU::getSRegs(kvm_m_sregs *sregs) {
    sregs->other_sp = m_env->v7m.other_sp;
    sregs->vecbase = m_env->v7m.vecbase;
    sregs->basepri = m_env->v7m.basepri;
    sregs->control = m_env->v7m.control;
    sregs->current_sp = m_env->v7m.current_sp;
    sregs->exception = m_env->v7m.exception;
    sregs->pending_exception = m_env->v7m.pending_exception;
    sregs->thumb = m_env->thumb;
    // printf("sregs basepri=%#x\n", sregs->basepri);
    // printf("sregs control=%#x\n", sregs->control);

    return 0;
}

int VCPU::getOneReg(kvm_one_reg *reg) {
    void *uaddr = (void *) (long) reg->addr;
    /* We currently use nothing arch-specific in upper 32 bits */
    if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM >> 32)
        return -EINVAL;

    /* Register group 16 means we want a core register. */
    if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
        return get_core_reg(reg);

    //	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_FW)
    //		return kvm_arm_get_fw_reg(vcpu, reg);
    //
    //	if (is_timer_reg(reg->id))
    //		return get_timer_reg(vcpu, reg);
    if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_VFP)
        return vfp_get_reg(reg->id, uaddr);

    return (reg->id & KVM_REG_ARM_COPROC_MASK);
}

int VCPU::getMPState(kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}

inline long VCPU::copy_from_user(void *to, const void *from, unsigned long n) {
    memcpy(to, from, n);
    return 0;
}

inline long VCPU::copy_to_user(void *to, const void *from, unsigned long n) {
    memcpy(to, from, n);
    return 0;
}

uint64 VCPU::core_reg_offset_from_id(uint64 id) {
    return id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE);
}

int VCPU::set_core_reg(kvm_one_reg *reg) {
    uint32 *uaddr = (uint32 *) (long) reg->addr;

    uint64 off, val = 0;

    if (KVM_REG_SIZE(reg->id) != 4)
        return -ENOENT;

    /* Our ID is an index into the kvm_regs struct. */
    off = core_reg_offset_from_id(reg->id);
    if (off >= sizeof(struct kvm_regs) / KVM_REG_SIZE(reg->id))
        return -ENOENT;

    val = *uaddr;
    //	if (get_user(val, uaddr) != 0)
    //		return -EFAULT;

    //	if (off == KVM_REG_ARM_CORE_REG(usr_regs.ARM_cpsr)) {
    //		unsigned long mode = val & MODE_MASK;
    //		switch (mode) {
    //		case USR_MODE:
    //		case FIQ_MODE:
    //		case IRQ_MODE:
    //		case SVC_MODE:
    //		case ABT_MODE:
    //		case UND_MODE:
    //			break;
    //		default:
    //			return -EINVAL;
    //		}
    //	}

    ((uint32 *) m_env->regs)[off] = val;
    return 0;
}

int VCPU::get_core_reg(kvm_one_reg *reg) {
    uint32 *uaddr = (uint32 *) (long) reg->addr;

    uint64 off;

    if (KVM_REG_SIZE(reg->id) != 4)
        return -ENOENT;

    /* Our ID is an index into the kvm_regs struct. */
    off = core_reg_offset_from_id(reg->id);
    if (off >= sizeof(m_env->regs) / KVM_REG_SIZE(reg->id))
        return -ENOENT;

    uaddr = &m_env->regs[off];
    return 0;
}

int VCPU::reg_from_user(void *val, const void *uaddr, uint64 id) {
    if (copy_from_user(val, uaddr, KVM_REG_SIZE(id)) != 0)
        return -EFAULT;
    return 0;
}

/*
 * Writes a register value to a userspace address from a kernel variable.
 * Make sure that register size matches sizeof(*__val).
 */
int VCPU::reg_to_user(void *uaddr, const void *val, uint64 id) {
    if (copy_to_user(uaddr, val, KVM_REG_SIZE(id)) != 0)
        return -EFAULT;
    return 0;
}

int VCPU::vfp_set_reg(uint64 id, const void *uaddr) {
    uint32 vfpid = (id & KVM_REG_ARM_VFP_MASK);

    /* Fail if we have unknown bits set. */
    if (id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_COPROC_MASK | ((1 << KVM_REG_ARM_COPROC_SHIFT) - 1)))
        return -ENOENT;

    if (vfpid < 16) {
        if (KVM_REG_SIZE(id) != 8)
            return -ENOENT;
        return reg_from_user(&m_env->vfp.xregs[vfpid], uaddr, id);
    }

    /* FP control registers are all 32 bit. */
    if (KVM_REG_SIZE(id) != 4)
        return -ENOENT;

    switch (vfpid) {
        case KVM_REG_ARM_VFP_FPEXC:
            return KVM_REG_ARM_VFP_FPEXC;
        case KVM_REG_ARM_VFP_FPSCR:
            return KVM_REG_ARM_VFP_FPSCR;
        case KVM_REG_ARM_VFP_FPINST:
            return KVM_REG_ARM_VFP_FPINST;
        case KVM_REG_ARM_VFP_FPINST2:
            return KVM_REG_ARM_VFP_FPINST2;
        /* These are invariant. */
        //	case KVM_REG_ARM_VFP_MVFR0:
        //		if (reg_from_user(&val, uaddr, id))
        //			return -EFAULT;
        //		if (val != fmrx(MVFR0))
        //			return -EINVAL;
        //		return 0;
        //	case KVM_REG_ARM_VFP_MVFR1:
        //		if (reg_from_user(&val, uaddr, id))
        //			return -EFAULT;
        //		if (val != fmrx(MVFR1))
        //			return -EINVAL;
        //		return 0;
        //	case KVM_REG_ARM_VFP_FPSID:
        //		if (reg_from_user(&val, uaddr, id))
        //			return -EFAULT;
        //		if (val != fmrx(FPSID))
        //			return -EINVAL;
        //		return 0;
        default:
            return -ENOENT;
    }
}

int VCPU::vfp_get_reg(uint64 id, void *uaddr) {

    uint32 vfpid = (id & KVM_REG_ARM_VFP_MASK);

    /* Fail if we have unknown bits set. */
    if (id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_COPROC_MASK | ((1 << KVM_REG_ARM_COPROC_SHIFT) - 1)))
        return -ENOENT;

    if (vfpid < 16) {
        if (KVM_REG_SIZE(id) != 8)
            return -ENOENT;
        return reg_to_user(uaddr, &m_env->vfp.xregs[vfpid], id);
        return 0;
    }

    /* FP control registers are all 32 bit. */
    if (KVM_REG_SIZE(id) != 4)
        return -ENOENT;

    switch (vfpid) {
        case KVM_REG_ARM_VFP_FPEXC:
            // return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpexc, id);
            return KVM_REG_ARM_VFP_FPEXC;
        case KVM_REG_ARM_VFP_FPSCR:
            // return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpscr, id);
            return KVM_REG_ARM_VFP_FPSCR;
        case KVM_REG_ARM_VFP_FPINST:
            // return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpinst, id);
            return KVM_REG_ARM_VFP_FPINST;
        case KVM_REG_ARM_VFP_FPINST2:
            // return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpinst2, id);
            return KVM_REG_ARM_VFP_FPINST2;
        //	case KVM_REG_ARM_VFP_MVFR0:
        //		val = fmrx(MVFR0);
        //		return reg_to_user(uaddr, &val, id);
        //	case KVM_REG_ARM_VFP_MVFR1:
        //		val = fmrx(MVFR1);
        //		return reg_to_user(uaddr, &val, id);
        //	case KVM_REG_ARM_VFP_FPSID:
        //		val = fmrx(FPSID);
        //		return reg_to_user(uaddr, &val, id);
        default:
            return -ENOENT;
    }
}

int VCPU::init(kvm_vcpu_init *init) {
    // have not been implemented, so firmware with cortex-A arch may not be successfully init
    return -1;
}

int VCPU::setIrqLine(kvm_irq_level *irq_level) {

    bool level = irq_level->level;
    arm_cpu_set_irq(m_env, level);
    return 0;
}

}
}
