//===-- AddressSpace.h ------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_ADDRESSSPACE_H
#define KLEE_ADDRESSSPACE_H

#include "klee/Expr.h"
#include "klee/IAddressSpaceNotification.h"
#include "klee/Internal/ADT/ImmutableMap.h"
#include "klee/Memory.h"

namespace klee {

class ExecutionState;
class ObjectState;

typedef std::vector<ObjectStatePtr> ResolutionList;

typedef ImmutableMap<ObjectKey, ObjectStatePtr> MemoryMap;

class AddressSpace {

    class Cache {
        static const unsigned CACHE_SIZE = 256;
        std::vector<ObjectStatePtr> m_cache;

        static inline uint8_t hash(uint64_t address) {
            uint8_t result = 0;
            int q = 33149;
            for (unsigned i = 0; i < 8; ++i) {
                result ^= (uint8_t) ((address & 0xFF) * q);
                address >>= 8;
            }
            return result;
        }

    public:
        Cache() {
            m_cache.resize(CACHE_SIZE);
        }

        Cache(const Cache &b) {
            m_cache.clear();
        }

        inline ObjectStatePtr get(uint64_t address) const {
            auto ret = m_cache[hash(address)];
            if (ret && ret->getAddress() == address) {
                return ret;
            }
            return nullptr;
        }

        inline void add(const ObjectStatePtr &os) {
            m_cache[hash(os->getAddress())] = os;
        }

        inline void invalidate(uint64_t address) {
            m_cache[hash(address)] = nullptr;
        }
    };

public:
    // Translates an address to a host address suitable for AddressSpace.
    using AddressTranslator = std::function<bool(uint64_t, uint64_t &)>;

private:
    /// Epoch counter used to control ownership of objects.
    mutable unsigned cowKey;

    mutable Cache m_cache;

    using IterateCb = std::function<bool(ObjectStateConstPtr &, unsigned offset, unsigned size)>;
    bool iterateRead(uintptr_t hostAddress, size_t size, IterateCb cb, AddressTranslator tr);

    using IterateWriteCb = std::function<bool(ObjectStatePtr &, unsigned offset, unsigned size)>;
    bool iterateWrite(uintptr_t hostAddress, size_t size, IterateWriteCb cb, AddressTranslator tr);

protected:
    /// Unsupported, use copy constructor
    AddressSpace &operator=(const AddressSpace &);

    ObjectStatePtr getWriteableInternal(const ObjectStateConstPtr &os);

    void updateWritable(const ObjectStateConstPtr &os, const ObjectStatePtr &wos);

    void addressSpaceChange(const klee::ObjectKey &key, const ObjectStateConstPtr &oldState,
                            const ObjectStatePtr &newState);

public:
    /// The MemoryObject -> ObjectState map that constitutes the
    /// address space.
    ///
    /// The set of objects where o->copyOnWriteOwner == cowKey are the
    /// objects that we own.
    ///
    /// \invariant forall o in objects, o->copyOnWriteOwner <= cowKey
    MemoryMap objects;

    /// ExecutionState that owns this AddressSpace
    IAddressSpaceNotification *state;

public:
    AddressSpace(IAddressSpaceNotification *_state) : cowKey(1), state(_state) {
    }

    AddressSpace(const AddressSpace &b) : cowKey(++b.cowKey), objects(b.objects) {
    }

    ~AddressSpace() {
    }

    /// Add a binding to the address space.
    void bindObject(const ObjectStatePtr &os);

    /// Remove a binding from the address space.
    void unbindObject(const ObjectKey &key);

    const ObjectStateConstPtr findObject(uint64_t address) const;

    /// Resolve address to an ObjectPair in result.
    /// \return true iff an object was found.
    bool findObject(uint64_t address, unsigned size, ObjectStateConstPtr &result, bool &inBounds);

    bool isOwnedByUs(const ObjectStateConstPtr &os) const {
        return cowKey == os->getOwnerId();
    }

    /// When a symbolic memory address references an object
    /// that is too big, split it to simplify the task of
    /// the constraint solver.
    bool splitMemoryObject(IAddressSpaceNotification &state, const ObjectStateConstPtr &object, ResolutionList &rl);

    /// \brief Obtain an ObjectState suitable for writing.
    ///
    /// This returns a writeable object state, creating a new copy of
    /// the given ObjectState if necessary. If the address space owns
    /// the ObjectState then this routine effectively just strips the
    /// const qualifier it.
    ///
    /// \param mo The MemoryObject to get a writeable ObjectState for.
    /// \param os The current binding of the MemoryObject.
    /// \return A writeable ObjectState (\a os or a copy).
    ObjectStatePtr getWriteable(const ObjectStateConstPtr &os);

    using Concretizer = std::function<uint8_t(const ref<Expr> &, const ObjectStateConstPtr &, size_t)>;

    bool read(uintptr_t address, uint8_t *buffer, size_t size, Concretizer c, AddressTranslator tr = nullptr);

    bool read(uintptr_t address, std::vector<ref<Expr>> &data, size_t size, AddressTranslator tr = nullptr);

    ref<Expr> read(uintptr_t address, Expr::Width width, AddressTranslator tr = nullptr);

    bool write(uintptr_t address, const uint8_t *buffer, size_t size, AddressTranslator tr = nullptr);

    bool write(uintptr_t address, const ref<Expr> &data, Concretizer c, AddressTranslator tr = nullptr);

    bool symbolic(uintptr_t address, size_t size, AddressTranslator tr = nullptr);
};

} // namespace klee

#endif
