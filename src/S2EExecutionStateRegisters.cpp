///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/Utils.h>

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>

// XXX: The idea is to avoid function calls
//#define small_memcpy(dest, source, count) asm volatile ("cld; rep movsb"::"S"(source), "D"(dest), "c" (count):"flags",
//"memory")
#define small_memcpy __builtin_memcpy

extern llvm::cl::opt<bool> PrintModeSwitch;

namespace s2e {

using namespace klee;

MemoryObject *S2EExecutionStateRegisters::s_concreteRegs = NULL;
MemoryObject *S2EExecutionStateRegisters::s_symbolicRegs = NULL;

void S2EExecutionStateRegisters::initialize(klee::AddressSpace &addressSpace, klee::MemoryObject *symbolicRegs,
                                            klee::MemoryObject *concreteRegs) {
    assert(!s_concreteRegs && !s_symbolicRegs);
    s_concreteRegs = concreteRegs;
    s_symbolicRegs = symbolicRegs;

    s_concreteRegs->setName("ConcreteCpuRegisters");
    s_symbolicRegs->setName("SymbolicCpuRegisters");

    /* The fast path in the cpu loop relies on this */
    s_symbolicRegs->doNotifyOnConcretenessChange = true;

    update(addressSpace, NULL, NULL, NULL, NULL);
}

void S2EExecutionStateRegisters::update(klee::AddressSpace &addressSpace, const bool *active,
                                        const bool *running_concrete, klee::IAddressSpaceNotification *notification,
                                        klee::IConcretizer *concretizer) {
    const ObjectState *concreteState = addressSpace.findObject(s_concreteRegs);
    const ObjectState *symbolicState = addressSpace.findObject(s_symbolicRegs);
    addressSpace.addCachedObject(s_concreteRegs, concreteState);
    addressSpace.addCachedObject(s_symbolicRegs, symbolicState);

    m_symbolicRegs = addressSpace.getWriteable(s_symbolicRegs, symbolicState);
    m_concreteRegs = addressSpace.getWriteable(s_concreteRegs, concreteState);

    if (active && running_concrete) {
        m_runningConcrete = running_concrete;
        m_active = active;
        m_notification = notification;
        m_concretizer = concretizer;
    }
}

void S2EExecutionStateRegisters::copySymbRegs(bool toNative) {
    // It is allowed to have mixed/concrete symbolic register state.
    // All register accesses are wrapped, so it is ok.
    // assert(m_symbolicRegs->isAllConcrete());

    if (toNative) {
        assert(!*m_runningConcrete);
        memcpy((void *) s_symbolicRegs->address, m_symbolicRegs->getConcreteStore(true), m_symbolicRegs->size);
    } else {
        assert(*m_runningConcrete);
        memcpy(m_symbolicRegs->getConcreteStore(true), (void *) s_symbolicRegs->address, m_symbolicRegs->size);
    }
}

CPUX86State *S2EExecutionStateRegisters::getNativeCpuState() const {
    return (CPUX86State *) (s_concreteRegs->address - CPU_OFFSET(eip));
}

// XXX: The returned pointer cannot be used to modify symbolic state
// It's gonna crash the system. We should really fix that.
CPUX86State *S2EExecutionStateRegisters::getCpuState() const {
    CPUX86State *cpu = *m_active
                           ? (CPUX86State *) (s_concreteRegs->address - offsetof(CPUX86State, eip))
                           : (CPUX86State *) (m_concreteRegs->getConcreteStore(true) - offsetof(CPUX86State, eip));

    return cpu;
}

void S2EExecutionStateRegisters::addressSpaceChange(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                                                    klee::ObjectState *newState) {
    if (mo == s_concreteRegs) {
        // It may happen that an execution state is copied in other places
        // than fork, in which case clone() is not called and the state
        // is left with stale references to memory objects. We patch these
        // objects here.
        m_concreteRegs = newState;
    } else if (mo == s_symbolicRegs) {
        m_symbolicRegs = newState;
    }
}

bool S2EExecutionStateRegisters::flagsRegistersAreSymbolic() const {
    if (m_symbolicRegs->isAllConcrete())
        return false;

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_op), sizeof(env->cc_op) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_src), sizeof(env->cc_src) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_dst), sizeof(env->cc_dst) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_tmp), sizeof(env->cc_tmp) * 8)) {
        return true;
    }

    return false;
}

uint64_t S2EExecutionStateRegisters::getSymbolicRegistersMask() const {
    if (m_symbolicRegs->isAllConcrete())
        return 0;

    uint64_t mask = 0;
    uint64_t offset = 0;
    /* XXX: x86-specific */
    for (int i = 0; i < CPU_NB_REGS; ++i) { /* regs */
        if (!m_symbolicRegs->isConcrete(offset, sizeof(*env->regs) * 8)) {
            mask |= (1 << (i + 5));
        }
        offset += sizeof(*env->regs);
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_op), sizeof(env->cc_op) * 8)) // cc_op
        mask |= _M_CC_OP;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_src), sizeof(env->cc_src) * 8)) // cc_src
        mask |= _M_CC_SRC;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_dst), sizeof(env->cc_dst) * 8)) // cc_dst
        mask |= _M_CC_DST;
    if (!m_symbolicRegs->isConcrete(offsetof(CPUX86State, cc_tmp), sizeof(env->cc_tmp) * 8)) // cc_tmp
        mask |= _M_CC_TMP;
    return mask;
}

bool S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, void *_buf, unsigned size, bool concretize) const {
    static const char *regNames[] = {"eax", "ecx", "edx",   "ebx",    "esp",    "ebp",
                                     "esi", "edi", "cc_op", "cc_src", "cc_dst", "cc_tmp"};
    assert(*m_active);
    // assert(((uint64_t) env) == s_symbolicRegs->address);
    assert(offset + size <= CPU_OFFSET(eip));

    /* Simple case, the register is concrete */
    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        // XXX: check if the size if always small enough
        small_memcpy(_buf, ((uint8_t *) env) + offset, size);
        return true;
    }

    /* Deal with the symbolic case */
    ObjectState *wos = m_symbolicRegs;
    bool oldAllConcrete = wos->isAllConcrete();

    // XXX: deal with alignment and overlaps?

    ref<Expr> value = wos->read(offset, size * 8);
    uint64_t concreteValue;
    if (!isa<ConstantExpr>(value)) {
        if (!concretize) {
            return false;
        }
        std::string reason =
            std::string("access to ") + regNames[offset / sizeof(target_ulong)] + " register from libcpu helper";

        concreteValue = m_concretizer->concretize(value, reason.c_str());
        wos->write(offset, ConstantExpr::create(concreteValue, size * 8));
    } else {
        ConstantExpr *ce = dyn_cast<ConstantExpr>(value);
        concreteValue = ce->getZExtValue(size * 8);
    }

    bool newAllConcrete = wos->isAllConcrete();
    if ((oldAllConcrete != newAllConcrete) && (wos->getObject()->doNotifyOnConcretenessChange)) {
        m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
    }

    // XXX: endianness issues on the host...
    small_memcpy(_buf, &concreteValue, size);

#ifdef S2E_TRACE_EFLAGS
    if (offsetof(CPUX86State, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "read conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif

    return true;
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, const void *_buf, unsigned size) {
    assert(*m_active);
    assert(((uint64_t) env) == s_symbolicRegs->address);
    assert(offset + size <= CPU_OFFSET(eip));

    const uint8_t *buf = (const uint8_t *) _buf;

    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        small_memcpy(((uint8_t *) env) + offset, buf, size);
    } else {

        ObjectState *wos = m_symbolicRegs;
        bool oldAllConcrete = wos->isAllConcrete();

        for (unsigned i = 0; i < size; ++i)
            wos->write8(offset + i, buf[i]);

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->getObject()->doNotifyOnConcretenessChange)) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }
    }

#ifdef S2E_TRACE_EFLAGS
    if (offsetof(CPUX86State, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "write conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif
}

ref<Expr> S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, Expr::Width width) const {
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));

    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        return m_symbolicRegs->read(offset, width);
    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        uint64_t ret = 0;
        small_memcpy((void *) &ret, (void *) (s_symbolicRegs->address + offset), Expr::getMinBytesForWidth(width));
        return ConstantExpr::create(ret, width);
    }
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));

    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

        m_symbolicRegs->write(offset, value);

        bool newAllConcrete = m_symbolicRegs->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->getObject()->doNotifyOnConcretenessChange)) {
            m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
        }

    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        /* XXX: why don't we allow writing symbolic values here ??? */
        assert(isa<ConstantExpr>(value) && "Cannot write symbolic values to registers while executing"
                                           " in concrete mode. TODO: fix it by fast_longjmping to main loop");
        ConstantExpr *ce = cast<ConstantExpr>(value);
        uint64_t v = ce->getZExtValue(64);
        small_memcpy((void *) (s_symbolicRegs->address + offset), (void *) &v,
                     Expr::getMinBytesForWidth(ce->getWidth()));
    }
}

// XXX: this must be used carefully, especially when running in concrete mode.
// Normally used from concrete helpers to manipulate symbolic data punctually.
void S2EExecutionStateRegisters::writeSymbolicRegionUnsafe(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));

    bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

    m_symbolicRegs->write(offset, value);

    bool newAllConcrete = m_symbolicRegs->isAllConcrete();
    if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->getObject()->doNotifyOnConcretenessChange)) {
        m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
    }
}

/***/

void S2EExecutionStateRegisters::readConcreteRegion(unsigned offset, void *buffer, unsigned size) const {
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    const uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(eip);
    } else {
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(eip);
    }

    small_memcpy(buffer, address + offset, size);
}

void S2EExecutionStateRegisters::writeConcreteRegion(unsigned offset, const void *buffer, unsigned size) {
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs->address - CPU_OFFSET(eip);
    } else {
        address = m_concreteRegs->getConcreteStore();
        assert(address);
        address -= CPU_OFFSET(eip);
    }

    small_memcpy(address + offset, buffer, size);
}

bool S2EExecutionStateRegisters::isConcreteRegion(unsigned offset) {
    return offset >= offsetof(CPUX86State, eip);
}

/**
 * The architectural part of the concrete portion of CPUState contains the COMMON stuff.
 * We skip this stuff in the comparison.
 */
int S2EExecutionStateRegisters::compareArchitecturalConcreteState(const S2EExecutionStateRegisters &other) {
    CPUX86State *a = getCpuState();
    CPUX86State *b = other.getCpuState();

    int ret = memcmp(&a->eip, &b->eip, CPU_OFFSET(se_common_start) - CPU_OFFSET(eip));
    if (ret) {
        return ret;
    }

    ret = memcmp(&a->se_common_end, &b->se_common_end, sizeof(CPUX86State) - CPU_OFFSET(se_common_end));
    return ret;
}

/***/

void S2EExecutionStateRegisters::read(unsigned offset, void *buffer, unsigned size) const {
    if (isConcreteRegion(offset)) {
        readConcreteRegion(offset, buffer, size);
    } else {
        readSymbolicRegion(offset, buffer, size, true);
    }
}

void S2EExecutionStateRegisters::write(unsigned offset, const void *buffer, unsigned size) {
    if (isConcreteRegion(offset)) {
        writeConcreteRegion(offset, buffer, size);
    } else {
        writeSymbolicRegion(offset, buffer, size);
    }
}

void S2EExecutionStateRegisters::write(unsigned offset, const klee::ref<klee::Expr> &value) {
    if (isConcreteRegion(offset)) {
        uint64_t val = m_concretizer->concretize(value, "Writing symbolic value to concrete area");
        writeConcreteRegion(offset, &val, value->getMinBytesForWidth(value->getWidth()));
    } else {
        writeSymbolicRegion(offset, value);
    }
}

// Get the program counter in the current state.
// Allows plugins to retrieve it in a hardware-independent manner.
uint64_t S2EExecutionStateRegisters::getPc() const {
    return read<target_ulong>(CPU_OFFSET(eip));
}

uint64_t S2EExecutionStateRegisters::getFlags() {
    /* restore flags in standard format */
    cpu_restore_eflags(env);
    return cpu_get_eflags(env);
}

void S2EExecutionStateRegisters::setPc(uint64_t pc) {
    write<target_ulong>(CPU_OFFSET(eip), pc);
}

void S2EExecutionStateRegisters::setSp(uint64_t sp) {
    write<target_ulong>(CPU_OFFSET(regs[R_ESP]), sp);
}

void S2EExecutionStateRegisters::setBp(uint64_t bp) {
    write<target_ulong>(CPU_OFFSET(regs[R_EBP]), bp);
}

uint64_t S2EExecutionStateRegisters::getSp() const {
    return read<target_ulong>(CPU_OFFSET(regs[R_ESP]));
}

uint64_t S2EExecutionStateRegisters::getBp() const {
    return read<target_ulong>(CPU_OFFSET(regs[R_EBP]));
}

uint64_t S2EExecutionStateRegisters::getPageDir() const {
    return read<target_ulong>(CPU_OFFSET(cr[3]));
}

/// \brief Print register values
///
/// \param ss output stream
///
void S2EExecutionStateRegisters::dump(std::ostream &ss) const {
    std::ostringstream concreteBytes;
    std::ostringstream symbolicBytes;

#define PRINT_REG(name)                                                                          \
    do {                                                                                         \
        ref<Expr> reg;                                                                           \
        /* TODO: use state->getPointerWidth() instead of Expr::Int32. */                         \
        /* It currenly fails because se_current_tb is NULL after state switch. */                \
        reg = readSymbolicRegion(CPU_OFFSET(regs[R_##name]), Expr::Int32);                       \
        concreteBytes << #name << " ";                                                           \
        for (int i = reg->getWidth() / CHAR_BIT - 1; i >= 0; i--) {                              \
            ref<Expr> byte = E_EXTR(reg, i * CHAR_BIT, Expr::Int8);                              \
            if (isa<ConstantExpr>(byte)) {                                                       \
                concreteBytes << hexval(dyn_cast<ConstantExpr>(byte)->getZExtValue(), 2, false); \
            } else {                                                                             \
                concreteBytes << "SS";                                                           \
                symbolicBytes << #name << "[" << i << "] " << byte << "\n";                      \
            }                                                                                    \
        }                                                                                        \
        concreteBytes << "\n";                                                                   \
    } while (0)

    PRINT_REG(EAX);
    PRINT_REG(EBX);
    PRINT_REG(ECX);
    PRINT_REG(EDX);
    PRINT_REG(ESI);
    PRINT_REG(EDI);
    PRINT_REG(EBP);
    PRINT_REG(ESP);

    ss << "Registers\n" << concreteBytes.str() << symbolicBytes.str();
}
}
