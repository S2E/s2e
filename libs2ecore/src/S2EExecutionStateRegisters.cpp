///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/Utils.h>

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>

//DIV reg represent the start regs of the concrete area of the CPU State
//everything beyond DIV reg must be concrete
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#define DIV eip
#elif defined(TARGET_ARM)
#define DIV regs[15]
#else
#error Unsupported target architecture
#endif

// XXX: The idea is to avoid function calls
//#define small_memcpy(dest, source, count) asm volatile ("cld; rep movsb"::"S"(source), "D"(dest), "c" (count):"flags",
//"memory")
#define small_memcpy __builtin_memcpy

extern llvm::cl::opt<bool> PrintModeSwitch;

namespace s2e {

using namespace klee;

ObjectKey S2EExecutionStateRegisters::s_concreteRegs;
ObjectKey S2EExecutionStateRegisters::s_symbolicRegs;

void S2EExecutionStateRegisters::initialize(klee::AddressSpace &addressSpace, const klee::ObjectStatePtr &symbolicRegs,
                                            const klee::ObjectStatePtr &concreteRegs) {
    assert(!s_concreteRegs.address && !s_symbolicRegs.address);
    s_concreteRegs = concreteRegs->getKey();
    s_symbolicRegs = symbolicRegs->getKey();

    symbolicRegs->setName("SymbolicCpuRegisters");
    concreteRegs->setName("ConcreteCpuRegisters");

    /* The fast path in the cpu loop relies on this */
    symbolicRegs->setNotifyOnConcretenessChange(true);

    update(addressSpace, nullptr, nullptr, nullptr, nullptr);
}

void S2EExecutionStateRegisters::update(klee::AddressSpace &addressSpace, const bool *active,
                                        const bool *running_concrete, klee::IAddressSpaceNotification *notification,
                                        klee::IConcretizer *concretizer) {
    auto concreteState = addressSpace.findObject(s_concreteRegs.address);
    auto symbolicState = addressSpace.findObject(s_symbolicRegs.address);

    m_symbolicRegs = addressSpace.getWriteable(symbolicState);
    m_concreteRegs = addressSpace.getWriteable(concreteState);

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
        memcpy((void *) s_symbolicRegs.address, m_symbolicRegs->getConcreteBuffer(true), m_symbolicRegs->getSize());
    } else {
        assert(*m_runningConcrete);
        memcpy(m_symbolicRegs->getConcreteBuffer(true), (void *) s_symbolicRegs.address, m_symbolicRegs->getSize());
    }
}

// XXX: The returned pointer cannot be used to modify symbolic state
// It's gonna crash the system. We should really fix that.
CPUArchState *S2EExecutionStateRegisters::getCpuState() const {
    CPUArchState *cpu = *m_active
                           ? (CPUArchState *) (s_concreteRegs.address - offsetof(CPUArchState, DIV))
                           : (CPUArchState *) (m_concreteRegs->getConcreteBuffer(true) - offsetof(CPUArchState, DIV));

    return cpu;
}

bool S2EExecutionStateRegisters::addressSpaceChange(const klee::ObjectKey &key,
                                                    const klee::ObjectStateConstPtr &oldState,
                                                    const klee::ObjectStatePtr &newState) {
    if (key == s_concreteRegs) {
        // It may happen that an execution state is copied in other places
        // than fork, in which case clone() is not called and the state
        // is left with stale references to memory objects. We patch these
        // objects here.
        m_concreteRegs = newState;
        assert(newState);
        return true;
    } else if (key == s_symbolicRegs) {
        m_symbolicRegs = newState;
        assert(newState);
        return true;
    } else {
        return false;
    }
}
#if defined(TARGET_I386) || defined(TARGET_X86_64)
bool S2EExecutionStateRegisters::flagsRegistersAreSymbolic() const {
    if (m_symbolicRegs->isAllConcrete())
        return false;

    if (!m_symbolicRegs->isConcrete(offsetof(CPUArchState, cc_op), sizeof(env->cc_op) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUArchState, cc_src), sizeof(env->cc_src) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUArchState, cc_dst), sizeof(env->cc_dst) * 8)) {
        return true;
    }

    if (!m_symbolicRegs->isConcrete(offsetof(CPUArchState, cc_tmp), sizeof(env->cc_tmp) * 8)) {
        return true;
    }

    return false;
}
#endif

bool S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, void *_buf, unsigned size, bool concretize) const {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    static const char *regNames[] = {"eax", "ecx", "edx",   "ebx",    "esp",    "ebp",
                                     "esi", "edi", "cc_op", "cc_src", "cc_dst", "cc_tmp"};
#elif defined(TARGET_ARM)
    static const char *regNames[] = {"regs[0]", "regs[1]", "regs[2]", "regs[3]", "regs[4]", "regs[5]",
                                     "regs[6]", "regs[7]", "regs[8]", "regs[9]", "regs[10]", "regs[11]",
                                     "regs[12]"};
#else
#error Unsupported target architecture
#endif
 
    assert(*m_active);
    // assert(((uint64_t) env) == s_symbolicRegs->address);
    assert(offset + size <= CPU_OFFSET(DIV));


    /* Simple case, the register is concrete */
    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        // XXX: check if the size if always small enough
        small_memcpy(_buf, ((uint8_t *) env) + offset, size);
        return true;
    }

    /* Deal with the symbolic case */
    auto wos = m_symbolicRegs;
    bool oldAllConcrete = wos->isAllConcrete();

    // XXX: deal with alignment and overlaps?

    // m_concretizer->concretize require value size <= sizeof(uint64_t), to
    // support data size > sizeof(uint64_t), we do concretization every
    // sizeof(uint64_t) bytes in a loop, or we can rewrite m_concretizer->concretize
    // to remove the sizeof(uint64_t) bytes limitation
    for (unsigned i = 0; i < size; i += sizeof(uint64_t)) {
        unsigned csize = (size - i) > sizeof(uint64_t) ? sizeof(uint64_t) : (size - i);
        ref<Expr> value = wos->read(offset + i, csize * 8);
        uint64_t concreteValue;
        if (!isa<ConstantExpr>(value)) {
            if (!concretize) {
                return false;
            }

            size_t regIndex = offset / sizeof(target_ulong);
            std::string regName = regIndex < (sizeof(regNames) / sizeof(regNames[0]))
                                      ? regNames[regIndex]
                                      : "CPUOffset-" + std::to_string(offset);
            std::string reason = "access to " + regName + " register from libcpu helper";

            concreteValue = m_concretizer->concretize(value, reason.c_str());
            wos->write(offset, ConstantExpr::create(concreteValue, csize * 8));
        } else {
            ConstantExpr *ce = dyn_cast<ConstantExpr>(value);
            concreteValue = ce->getZExtValue(csize * 8);
        }

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->notifyOnConcretenessChange())) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }

        // XXX: endianness issues on the host...
        small_memcpy((char *) _buf + i, &concreteValue, csize);
    }
#ifdef S2E_TRACE_EFLAGS
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    if (offsetof(CPUArchState, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "read conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif
#endif

    return true;
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, const void *_buf, unsigned size) {
    assert(*m_active);
    assert(((uint64_t) env) == s_symbolicRegs.address);
    assert(offset + size <= CPU_OFFSET(DIV));

    const uint8_t *buf = (const uint8_t *) _buf;

    if (likely(*m_runningConcrete &&
               (m_symbolicRegs->isAllConcrete() || m_symbolicRegs->isConcrete(offset, size * 8)))) {
        small_memcpy(((uint8_t *) env) + offset, buf, size);
    } else {

        auto wos = m_symbolicRegs;
        bool oldAllConcrete = wos->isAllConcrete();

        for (unsigned i = 0; i < size; ++i)
            wos->write8(offset + i, buf[i]);

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->notifyOnConcretenessChange())) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }
    }

#ifdef S2E_TRACE_EFLAGS
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    if (offsetof(CPUArchState, cc_src) == offset) {
        m_s2e->getDebugStream() << std::hex << getPc() << "write conc cc_src " << (*(uint32_t *) ((uint8_t *) buf))
                                << '\n';
    }
#endif
#endif
}

ref<Expr> S2EExecutionStateRegisters::readSymbolicRegion(unsigned offset, Expr::Width width) const {
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(DIV));

    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        klee::BitfieldSimplifier simpl;
        auto ret = m_symbolicRegs->read(offset, width);
        return simpl.simplify(ret);
    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        uint64_t ret = 0;
        small_memcpy((void *) &ret, (void *) (s_symbolicRegs.address + offset), Expr::getMinBytesForWidth(width));
        return ConstantExpr::create(ret, width);
    }
}

void S2EExecutionStateRegisters::writeSymbolicRegion(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(DIV));

    if (!(*m_runningConcrete) || !m_symbolicRegs->isConcrete(offset, width)) {
        bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

        m_symbolicRegs->write(offset, value);

        bool newAllConcrete = m_symbolicRegs->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->notifyOnConcretenessChange())) {
            m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
        }

    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        /* XXX: why don't we allow writing symbolic values here ??? */
        assert(isa<ConstantExpr>(value) && "Cannot write symbolic values to registers while executing"
                                           " in concrete mode. TODO: fix it by fast_longjmping to main loop");
        ConstantExpr *ce = cast<ConstantExpr>(value);
        uint64_t v = ce->getZExtValue(64);
        small_memcpy((void *) (s_symbolicRegs.address + offset), (void *) &v,
                     Expr::getMinBytesForWidth(ce->getWidth()));
    }
}

// XXX: this must be used carefully, especially when running in concrete mode.
// Normally used from concrete helpers to manipulate symbolic data punctually.
void S2EExecutionStateRegisters::writeSymbolicRegionUnsafe(unsigned offset, klee::ref<klee::Expr> value) {
    unsigned width = value->getWidth();
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(DIV));

    bool oldAllConcrete = m_symbolicRegs->isAllConcrete();

    m_symbolicRegs->write(offset, value);

    bool newAllConcrete = m_symbolicRegs->isAllConcrete();
    if ((oldAllConcrete != newAllConcrete) && (m_symbolicRegs->notifyOnConcretenessChange())) {
        m_notification->addressSpaceSymbolicStatusChange(m_symbolicRegs, newAllConcrete);
    }
}

/***/

void S2EExecutionStateRegisters::readConcreteRegion(unsigned offset, void *buffer, unsigned size) const {
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUArchState, DIV));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUArchState));

    const uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs.address - CPU_OFFSET(DIV);
    } else {
        address = m_concreteRegs->getConcreteBuffer();
        assert(address);
        address -= CPU_OFFSET(DIV);
    }

    small_memcpy(buffer, address + offset, size);
}

void S2EExecutionStateRegisters::writeConcreteRegion(unsigned offset, const void *buffer, unsigned size) {
    unsigned width = size * 8;
    assert((width == 1 || (width & 7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUArchState, DIV));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUArchState));

    uint8_t *address;
    if (*m_active) {
        address = (uint8_t *) s_concreteRegs.address - CPU_OFFSET(DIV);
    } else {
        address = m_concreteRegs->getConcreteBuffer();
        assert(address);
        address -= CPU_OFFSET(DIV);
    }

    small_memcpy(address + offset, buffer, size);
}

bool S2EExecutionStateRegisters::getRegionType(unsigned offset, unsigned size, bool *isConcrete) {
    if (offset + size <= offsetof(CPUArchState, DIV)) {
        *isConcrete = false;
        return true;
    } else if (offset >= offsetof(CPUArchState, DIV)) {
        *isConcrete = true;
        return true;
    } else {
        return false;
    }
}

/**
 * The architectural part of the concrete portion of CPUState contains the COMMON stuff.
 * We skip this stuff in the comparison.
 */
int S2EExecutionStateRegisters::compareArchitecturalConcreteState(const S2EExecutionStateRegisters &other) {
    CPUArchState *a = getCpuState();
    CPUArchState *b = other.getCpuState();

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    int ret = memcmp(&a->eip, &b->eip, CPU_OFFSET(se_common_start) - CPU_OFFSET(DIV));
#elif defined(TARGET_ARM)
    int ret = memcmp(&a->regs[15], &b->regs[15], CPU_OFFSET(se_common_start) - CPU_OFFSET(DIV));
#else
#error Unsupported target architecture
#endif

    if (ret) {
        return ret;
    }

    ret = memcmp(&a->se_common_end, &b->se_common_end, sizeof(CPUArchState) - CPU_OFFSET(se_common_end));
    return ret;
}

/***/

klee::ref<klee::Expr> S2EExecutionStateRegisters::read(unsigned offset, klee::Expr::Width width) const {
    bool isConcrete = false;
    unsigned size = klee::Expr::getMinBytesForWidth(width);
    if (!getRegionType(offset, size, &isConcrete)) {
        return nullptr;
    }

    if (isConcrete) {
        switch (width) {
            case klee::Expr::Bool:
                return klee::ConstantExpr::create(read<uint8>(offset) & 1, width);
            case klee::Expr::Int8:
                return klee::ConstantExpr::create(read<uint8>(offset), width);
            case klee::Expr::Int16:
                return klee::ConstantExpr::create(read<uint16>(offset), width);
            case klee::Expr::Int32:
                return klee::ConstantExpr::create(read<uint32>(offset), width);
            case klee::Expr::Int64:
                return klee::ConstantExpr::create(read<uint64>(offset), width);
            default:
                return nullptr;
        }
    } else {
        return readSymbolicRegion(offset, width);
    }
}

bool S2EExecutionStateRegisters::read(unsigned offset, void *buffer, unsigned size, bool concretize) const {
    bool isConcrete = false;
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        readConcreteRegion(offset, buffer, size);
        return true;
    } else {
        return readSymbolicRegion(offset, buffer, size, concretize);
    }
}

bool S2EExecutionStateRegisters::write(unsigned offset, const void *buffer, unsigned size) {
    bool isConcrete = false;
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        writeConcreteRegion(offset, buffer, size);
    } else {
        writeSymbolicRegion(offset, buffer, size);
    }

    return true;
}

bool S2EExecutionStateRegisters::write(unsigned offset, const klee::ref<klee::Expr> &value) {
    bool isConcrete = false;
    unsigned size = klee::Expr::getMinBytesForWidth(value->getWidth());
    if (!getRegionType(offset, size, &isConcrete)) {
        return false;
    }

    if (isConcrete) {
        uint64_t val = m_concretizer->concretize(value, "Writing symbolic value to concrete area");
        writeConcreteRegion(offset, &val, size);
    } else {
        writeSymbolicRegion(offset, value);
    }

    return true;
}

// Get the program counter in the current state.
// Allows plugins to retrieve it in a hardware-independent manner.
#if defined(TARGET_I386) || defined(TARGET_X86_64)
uint64_t S2EExecutionStateRegisters::getPc() const {
    return read<target_ulong>(CPU_OFFSET(eip));
}

void S2EExecutionStateRegisters::setPc(uint64_t pc) {
    bool ret = write<target_ulong>(CPU_OFFSET(eip), pc);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getSp() const {
    return read<target_ulong>(CPU_OFFSET(regs[R_ESP]));
}

void S2EExecutionStateRegisters::setSp(uint64_t sp) {
    bool ret = write<target_ulong>(CPU_OFFSET(regs[R_ESP]), sp);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getBp() const {
    return read<target_ulong>(CPU_OFFSET(regs[R_EBP]));
}

void S2EExecutionStateRegisters::setBp(uint64_t bp) {
    bool ret = write<target_ulong>(CPU_OFFSET(regs[R_EBP]), bp);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getPageDir() const {
    return read<target_ulong>(CPU_OFFSET(cr[3]));
}

uint64_t S2EExecutionStateRegisters::getFlags() {
    /* restore flags in standard format */
    cpu_restore_eflags(env);
    return cpu_get_eflags(env);
}
#elif defined(TARGET_ARM)
uint64_t S2EExecutionStateRegisters::getPc() const {
    return read<target_ulong>(CPU_OFFSET(regs[15]));
}

void S2EExecutionStateRegisters::setPc(uint64_t pc) {
    bool ret = write<target_ulong>(CPU_OFFSET(regs[15]), pc);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getSp() const {
    return read<target_ulong>(CPU_OFFSET(regs[13]));
}

void S2EExecutionStateRegisters::setSp(uint64_t sp) {
    bool ret = write<target_ulong>(CPU_OFFSET(regs[13]), sp);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getLr() const {
    return read<target_ulong>(CPU_OFFSET(regs[14]));
}

void S2EExecutionStateRegisters::setLr(uint64_t lr) {
    bool ret = write<target_ulong>(CPU_OFFSET(regs[14]), lr);
    assert(ret);
}

uint64_t S2EExecutionStateRegisters::getPageDir() const {
    return 0x0;
}

uint64_t S2EExecutionStateRegisters::getExceptionIndex() const {
    return read<target_ulong>(CPU_OFFSET(v7m.exception));
}

uint64_t S2EExecutionStateRegisters::getInterruptFlag() const {
    return read<target_ulong>(CPU_OFFSET(interrupt_flag));
}
#else
#error Unsupported target architecture
#endif



/// \brief Print register values
///
/// \param ss output stream
///
void S2EExecutionStateRegisters::dump(std::ostream &ss) const {
    std::ostringstream concreteBytes;
    std::ostringstream symbolicBytes;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#define PRINT_REG(name)                                                                          \
    do {                                                                                         \
        ref<Expr> reg;                                                                           \
        /* TODO: use state->getPointerWidth() instead of Expr::Int32. */                         \
        /* It currenly fails because se_current_tb is nullptr after state switch. */             \
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

#elif defined(TARGET_ARM)
#define PRINT_REG(name)                                                                          \
    do {                                                                                         \
        ref<Expr> reg;                                                                           \
        /* TODO: use state->getPointerWidth() instead of Expr::Int32. */                         \
        /* It currenly fails because se_current_tb is nullptr after state switch. */             \
        reg = readSymbolicRegion(CPU_OFFSET(regs[name]), Expr::Int32);                       \
        concreteBytes << name << " ";                                                           \
        for (int i = reg->getWidth() / CHAR_BIT - 1; i >= 0; i--) {                              \
            ref<Expr> byte = E_EXTR(reg, i * CHAR_BIT, Expr::Int8);                              \
            if (isa<ConstantExpr>(byte)) {                                                       \
                concreteBytes << hexval(dyn_cast<ConstantExpr>(byte)->getZExtValue(), 2, false); \
            } else {                                                                             \
                concreteBytes << "SS";                                                           \
                symbolicBytes << name << "[" << i << "] " << byte << "\n";                      \
            }                                                                                    \
        }                                                                                        \
        concreteBytes << "\n";                                                                   \
    } while (0)

    PRINT_REG(0);
    PRINT_REG(1);
    PRINT_REG(2);
    PRINT_REG(3);
    PRINT_REG(4);
    PRINT_REG(5);
    PRINT_REG(6);
#else
#error Unsupported target architecture
#endif

    ss << "Registers\n" << concreteBytes.str() << symbolicBytes.str();
}
} // namespace s2e
