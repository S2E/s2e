///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_REGISTERS_H_

#define S2E_REGISTERS_H_

#include <inttypes.h>
#include <klee/AddressSpace.h>
#include <klee/IAddressSpaceNotification.h>
#include <klee/IConcretizer.h>
#include <klee/Memory.h>

extern "C" {
struct CPUX86State;
}

#define CPU_OFFSET(field) offsetof(CPUX86State, field)

namespace s2e {

class S2EExecutionStateRegisters {
protected:
    /* Static because they do not change */
    static klee::MemoryObject *s_symbolicRegs;
    static klee::MemoryObject *s_concreteRegs;

    klee::ObjectState *m_symbolicRegs;
    klee::ObjectState *m_concreteRegs;

    const bool *m_active;
    const bool *m_runningConcrete;
    klee::IAddressSpaceNotification *m_notification;
    klee::IConcretizer *m_concretizer;

public:
    S2EExecutionStateRegisters(const bool *active, const bool *running_concrete,
                               klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer)
        : m_active(active), m_runningConcrete(running_concrete), m_notification(notification),
          m_concretizer(concretizer){};

    void initialize(klee::AddressSpace &addressSpace, klee::MemoryObject *symbolicRegs,
                    klee::MemoryObject *concreteRegs);

    void update(klee::AddressSpace &addressSpace, const bool *active, const bool *running_concrete,
                klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer);

    void copySymbRegs(bool toNative);

    int compareConcreteState(const S2EExecutionStateRegisters &other) {
        return memcmp(m_concreteRegs->getConcreteStore(), other.m_concreteRegs->getConcreteStore(),
                      s_concreteRegs->size);
    }

    int compareArchitecturalConcreteState(const S2EExecutionStateRegisters &other);

    inline void saveConcreteState() {
        memcpy((void *) m_concreteRegs->getConcreteStore(), (void *) s_concreteRegs->address, s_concreteRegs->size);
    }

    inline void restoreConcreteState() {
        memcpy((void *) s_concreteRegs->address, (void *) m_concreteRegs->getConcreteStore(), s_concreteRegs->size);
    }

    CPUX86State *getNativeCpuState() const;

    /**
     * Returns a pointer to the store where the concrete
     * data of the cpu registers reside. It can either point
     * to the backing store if the state is inactive, or to
     * the global CPUState object if active.
     */
    CPUX86State *getCpuState() const;

    bool allConcrete() const {
        return m_symbolicRegs->isAllConcrete();
    }

    /** Returns a mask of registers that contains symbolic values */
    uint64_t getSymbolicRegistersMask() const;

    bool flagsRegistersAreSymbolic() const;

    static bool initialized() {
        return s_concreteRegs != NULL && s_symbolicRegs != NULL;
    }

    /*****************************************************************/

    /** Read CPU general purpose register */
    klee::ref<klee::Expr> readSymbolicRegion(unsigned offset, klee::Expr::Width width) const;

    /**
     * Read concrete value from general purpose CPU register.
     * Return false if the data was symbolic and no concretization is request.
     */
    bool readSymbolicRegion(unsigned offset, void *buf, unsigned size, bool concretize = false) const;

    /*****************************************************************/

    /** Write CPU general purpose register */
    void writeSymbolicRegion(unsigned offset, klee::ref<klee::Expr> value);

    /**
     * Same as writeSymbolicRegion but also allows writing symbolic values
     * while running in concrete mode
     */
    void writeSymbolicRegionUnsafe(unsigned offset, klee::ref<klee::Expr> value);

    /** Write concrete value to general purpose CPU register */
    void writeSymbolicRegion(unsigned offset, const void *buf, unsigned size);

    /*****************************************************************/

    /** Read CPU system state, size is in bytes */
    void readConcreteRegion(unsigned offset, void *buffer, unsigned size) const;

    /** Write CPU system state, size is in bytes */
    void writeConcreteRegion(unsigned offset, const void *buffer, unsigned size);

    void read(unsigned offset, void *buffer, unsigned size) const;

    template <typename T> T read(unsigned offset) const {
        T ret;
        read(offset, &ret, sizeof(ret));
        return ret;
    }

    void write(unsigned offset, const void *buffer, unsigned size);
    void write(unsigned offset, const klee::ref<klee::Expr> &value);

    template <typename T> void write(unsigned offset, T value) {
        write(offset, &value, sizeof(T));
    }

    static bool isConcreteRegion(unsigned offset);

    uint64_t getPc() const;
    uint64_t getPageDir() const;
    uint64_t getSp() const;
    uint64_t getBp() const;
    uint64_t getFlags();

    void setPc(uint64_t pc);
    void setSp(uint64_t sp);
    void setBp(uint64_t bp);

    void addressSpaceChange(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                            klee::ObjectState *newState);

    static const klee::MemoryObject *getConcreteRegs() {
        return s_concreteRegs;
    }

    void dump(std::ostream &ss) const;
};
}

#endif
