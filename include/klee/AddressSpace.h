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

private:
    /// Epoch counter used to control ownership of objects.
    mutable unsigned cowKey;

protected:
    /// Unsupported, use copy constructor
    AddressSpace &operator=(const AddressSpace &);

    ObjectStatePtr getWriteableInternal(const ObjectStateConstPtr &os) {
        auto n = os->copy();
        n->setOwnerId(cowKey);

        // Clients must take into account the change
        // of location of the concrete buffer.
        assert(n->getKey() == os->getKey());
        addressSpaceChange(n->getKey(), os, n);

        ObjectKey key;
        key.address = os->getAddress();
        key.size = os->getSize();

        objects = objects.replace(std::make_pair(key, n));
        return n;
    }

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
    void unbindObject(const ObjectStateConstPtr &os);

    const ObjectStateConstPtr findObject(uint64_t address) const {
        ObjectKey key;
        key.address = address;
        key.size = 1;
        auto res = objects.lookup(key);
        return res ? res->second : 0;
    }

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

} // End klee namespace

#endif
