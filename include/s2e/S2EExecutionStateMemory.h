///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_EXECUTION_STATE_MEMORY

#define S2E_EXECUTION_STATE_MEMORY

#include <klee/IAddressSpaceNotification.h>
#include <klee/IConcretizer.h>
#include "AddressSpaceCache.h"

namespace s2e {

enum AddressType { VirtualAddress, PhysicalAddress, HostAddress };

class S2EExecutionStateMemory {

protected:
    static klee::MemoryObject *s_dirtyMask;
    klee::ObjectState *m_dirtyMask;
    const bool *m_active;
    AddressSpaceCache *m_asCache;
    klee::AddressSpace *m_addressSpace;
    klee::IAddressSpaceNotification *m_notification;
    klee::IConcretizer *m_concretizer;

    void transferRamInternalSymbolic(klee::ObjectPair op, uint64_t object_offset, klee::ref<klee::Expr> *buf,
                                     uint64_t size, bool write);

    void transferRamInternal(klee::ObjectPair op, uint64_t object_offset, uint8_t *buf, uint64_t size, bool write,
                             bool exitOnSymbolicRead);

public:
    S2EExecutionStateMemory();

    void initialize(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache, const bool *active,
                    klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer,
                    klee::MemoryObject *dirtyMask);

    void update(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache, const bool *active,
                klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer);

    /** Virtual address translation (debug mode). Returns -1 on failure. */
    uint64_t getPhysicalAddress(uint64_t virtualAddress) const;

    /** Address translation (debug mode). Returns host address or -1 on failure */
    uint64_t getHostAddress(uint64_t address, AddressType addressType = VirtualAddress) const;

    /** Read/write from physical memory, concretizing if necessary on reads.
        Note: this function accepts host address. Used by softmmu code. */
    void transferRam(struct CPUTLBRAMEntry *te, uint64_t hostAddress, void *buf, uint64_t size, bool isWrite,
                     bool exitOnSymbolicRead, bool isSymbolic);

    /** Read memory to buffer, concretize if necessary */
    bool readMemoryConcrete(uint64_t address, void *buf, uint64_t size, AddressType addressType = VirtualAddress);

    /** Write concrete buffer to memory */
    bool writeMemoryConcrete(uint64_t address, const void *buf, uint64_t size,
                             AddressType addressType = VirtualAddress);

    /** Access to state's memory. Address is virtual or physical,
        depending on 'physical' argument. Returns NULL or false in
        case of failure (can't resolve virtual address or physical
        address is invalid) */
    klee::ref<klee::Expr> readMemory(uint64_t address, klee::Expr::Width width,
                                     AddressType addressType = VirtualAddress);
    klee::ref<klee::Expr> readMemory8(uint64_t address, AddressType addressType = VirtualAddress);

    bool readMemoryConcrete8(uint64_t address, uint8_t *result = NULL, AddressType addressType = VirtualAddress,
                             bool addConstraint = true);

    bool writeMemory(uint64_t address, klee::ref<klee::Expr> value, AddressType addressType = VirtualAddress);

    bool writeMemory8(uint64_t address, klee::ref<klee::Expr> value, AddressType addressType = VirtualAddress);

    template <typename T> bool writeMemory(uint64_t address, T value, AddressType addressType = VirtualAddress) {
        return writeMemoryConcrete(address, (T *) &value, sizeof(T), addressType);
    }

    /** Dirty mask management */
    uint8_t readDirtyMask(uint64_t host_address);
    void writeDirtyMask(uint64_t host_address, uint8_t val);
    void registerDirtyMask(uint64_t host_address, uint64_t size);

    /** Read a generic string from memory */
    template <typename T> bool readGenericString(uint64_t address, std::string &s, unsigned maxLen) {
        s = "";
        bool ret = false;
        T c;

        do {
            c = 0;

            ret = readMemoryConcrete(address, &c, sizeof(c));
            maxLen--;
            address += sizeof(T);

            if (c) {
                s = s + (char) c;
            }

        } while (c && (maxLen > 0));

        return ret;
    }

    /** Read an ASCIIZ string from memory */
    bool readString(uint64_t address, std::string &s, unsigned maxLen = 256);

    /** Read a unicode string from memory */
    bool readUnicodeString(uint64_t address, std::string &s, unsigned maxLen = 256);

    static const klee::MemoryObject *getDirtyMask() {
        return s_dirtyMask;
    }

    uintptr_t getDirtyMaskStoreAddend() const {
        return (uintptr_t) m_dirtyMask->getConcreteStore(false) - s_dirtyMask->address;
    }

    klee::ObjectPair getMemoryObject(uint64_t address, AddressType addressType = VirtualAddress) const;
};

} // namespace s2e

#endif
