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
#include "ObjectHolder.h"

namespace klee {

class ExecutionState;
class MemoryObject;
class ObjectState;

typedef std::pair<const MemoryObject *, const ObjectState *> ObjectPair;
typedef std::pair<MemoryObject *, ObjectState *> MutableObjectPair;
typedef std::vector<ObjectPair> ResolutionList;

/// Function object ordering MemoryObject's by address and size.
struct MemoryObjectLTS {
    bool operator()(const MemoryObject *a, const MemoryObject *b) const;
};

typedef ImmutableMap<const MemoryObject *, ObjectHolder, MemoryObjectLTS> MemoryMap;

class AddressSpace {

private:
    /// Epoch counter used to control ownership of objects.
    mutable unsigned cowKey;

protected:
    /// Unsupported, use copy constructor
    AddressSpace &operator=(const AddressSpace &);

    ObjectState *getWriteableInternal(const MemoryObject *mo, const ObjectState *os) {
        ObjectState *n = new ObjectState(*os);
        n->copyOnWriteOwner = cowKey;

        // Clients must take into account the change
        // of location of the concrete buffer.
        addressSpaceChange(mo, os, n);

        objects = objects.replace(std::make_pair(mo, n));
        return n;
    }

    void updateWritable(const MemoryObject *mo, const ObjectState *os, ObjectState *wos);

    void addressSpaceChange(const MemoryObject *mo, const ObjectState *oldState, ObjectState *newState);

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
    void bindObject(const MemoryObject *mo, ObjectState *os);

    /// Remove a binding from the address space.
    void unbindObject(const MemoryObject *mo);

    /// Lookup a binding from a MemoryObject.
    const ObjectState *findObject(const MemoryObject *mo) const {
        auto res = objects.lookup(mo);
        return res ? res->second : 0;
    }

    /// Lookup a binding from a MemoryObject address.
    ObjectPair findObject(uint64_t address) const {
        MemoryObject hack(address);
        hack.size = 1;
        auto res = objects.lookup(&hack);
        return res ? ObjectPair(*res) : ObjectPair(NULL, NULL);
    }

    /// Resolve address to an ObjectPair in result.
    /// \return true iff an object was found.
    bool findObject(uint64_t address, unsigned size, ObjectPair &result, bool &inBounds);

    bool isOwnedByUs(const ObjectState *os) const {
        return cowKey == os->copyOnWriteOwner;
    }

    /// When a symbolic memory address references an object
    /// that is too big, split it to simplify the task of
    /// the constraint solver.
    bool splitMemoryObject(ExecutionState &state, const MemoryObject *originalObject, ResolutionList &rl);

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
    ObjectState *getWriteable(const MemoryObject *mo, const ObjectState *os);
};

} // End klee namespace

#endif
