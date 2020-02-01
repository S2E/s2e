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
                result ^= (uint8_t)((address & 0xFF) * q);
                address >>= 8;
            }
            return address;
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

private:
    /// Epoch counter used to control ownership of objects.
    mutable unsigned cowKey;

    mutable Cache m_cache;

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
    ExecutionState *state;

public:
    AddressSpace(ExecutionState *_state) : cowKey(1), state(_state) {
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
    bool splitMemoryObject(ExecutionState &state, const ObjectStateConstPtr &object, ResolutionList &rl);

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
};

} // namespace klee

#endif
