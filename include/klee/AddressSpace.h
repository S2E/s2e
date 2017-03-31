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

#include "ObjectHolder.h"

#include "klee/Expr.h"
#include "klee/Internal/ADT/ImmutableMap.h"

#include "klee/BitfieldSimplifier.h"

#include "klee/Memory.h"

namespace klee {
extern bool g_klee_address_space_preserve_concrete_buffer_address;

class ExecutionState;
class MemoryObject;
class ObjectState;
class TimingSolver;

template <class T> class ref;

typedef std::pair<const MemoryObject *, const ObjectState *> ObjectPair;
typedef std::vector<ObjectPair> ResolutionList;
typedef llvm::SmallVector<ObjectPair, 2> ObjectCache;

/// Function object ordering MemoryObject's by address.
struct MemoryObjectLT {
    bool operator()(const MemoryObject *a, const MemoryObject *b) const;
};

/// Function object ordering MemoryObject's by address and size.
struct MemoryObjectLTS {
    bool operator()(const MemoryObject *a, const MemoryObject *b) const;
};

typedef ImmutableMap<const MemoryObject *, ObjectHolder, MemoryObjectLT> MemoryMap;

template <typename LT> class AddressSpaceBase {

private:
    /// Epoch counter used to control ownership of objects.
    mutable unsigned cowKey;

protected:
    /// Unsupported, use copy constructor
    AddressSpaceBase &operator=(const AddressSpaceBase &);

    virtual void addressSpaceChange(const MemoryObject *mo, const ObjectState *oldState, ObjectState *newState){};

    ObjectState *getWriteableInternal(const MemoryObject *mo, const ObjectState *os) {
        ObjectState *n = new ObjectState(*os);
        n->copyOnWriteOwner = cowKey;

        if (g_klee_address_space_preserve_concrete_buffer_address) {
            MemoryMap::iterator it = objects.find(mo);
            assert(it != objects.end());

            const ObjectHolder &h = (*it).second;
            ObjectState *tmpState = h;
            ConcreteBuffer *tmp = tmpState->getConcreteBufferAs();
            (*h).replaceConcreteBuffer(n->getConcreteBufferAs());
            n->replaceConcreteBuffer(tmp);
        }

        // Clients must take into account the change
        // of location of the concrete buffer.
        addressSpaceChange(mo, os, n);

        objects = objects.replace(std::make_pair(mo, n));
        return n;
    }

    void updateWritable(const MemoryObject *mo, const ObjectState *os, ObjectState *wos);

public:
    /// The MemoryObject -> ObjectState map that constitutes the
    /// address space.
    ///
    /// The set of objects where o->copyOnWriteOwner == cowKey are the
    /// objects that we own.
    ///
    /// \invariant forall o in objects, o->copyOnWriteOwner <= cowKey
    ImmutableMap<const MemoryObject *, ObjectHolder, LT> objects;

public:
    AddressSpaceBase() : cowKey(1) {
    }
    AddressSpaceBase(const AddressSpaceBase &b) : cowKey(++b.cowKey), objects(b.objects) {
    }
    virtual ~AddressSpaceBase() {
    }

    /// Add a binding to the address space.
    void bindObject(const MemoryObject *mo, ObjectState *os) {
        const ObjectState *oldOS = findObject(mo);

        if (oldOS) {
            addressSpaceChange(mo, oldOS, NULL);
        }

        addressSpaceChange(mo, NULL, os);

        assert(os->copyOnWriteOwner == 0 && "object already has owner");

        os->copyOnWriteOwner = cowKey;
        objects = objects.replace(std::make_pair(mo, os));
    }

    /// Remove a binding from the address space.
    void unbindObject(const MemoryObject *mo) {
        const ObjectState *os = findObject(mo);

        if (os) {
            addressSpaceChange(mo, os, NULL);
        }

        objects = objects.remove(mo);
    }

    /// Lookup a binding from a MemoryObject.
    const ObjectState *findObject(const MemoryObject *mo) const {
        const MemoryMap::value_type *res = objects.lookup(mo);
        return res ? res->second : 0;
    }

    /// Lookup a binding from a MemoryObject address.
    ObjectPair findObject(uint64_t address) const {
        MemoryObject hack(address);
        const MemoryMap::value_type *res = objects.lookup(&hack);
        return res ? ObjectPair(*res) : ObjectPair(NULL, NULL);
    }

    virtual ObjectState *getWriteable(const MemoryObject *mo, const ObjectState *os) {
        assert(!os->readOnly);

        if (isOwnedByUs(os)) {
            return const_cast<ObjectState *>(os);
        }

        return getWriteableInternal(mo, os);
    }

    bool isOwnedByUs(const ObjectState *os) const {
        return cowKey == os->copyOnWriteOwner;
    }
};

typedef AddressSpaceBase<MemoryObjectLTS> AddressSpaceSz;

class AddressSpace : public AddressSpaceBase<MemoryObjectLT> {
public:
    /// When a symbolic memory address references an object
    /// that is too big, split it to simplify the task of
    /// the constraint solver.
    bool splitMemoryObject(ExecutionState &state, const MemoryObject *originalObject, ResolutionList &rl);

    /// Extracts known expression patterns from the symbolic
    /// address to quickly resolve the object.
    /// Supported patterns:
    ///    Concrete address
    ///        Will set inBounds to true if address + width falls in one object
    ///    Constant base address + offset
    ///        Will set inBounds to true if can prove statically for the symbolic address
    ///        without going through the constraint solver.
    bool resolveOneFast(BitfieldSimplifier &simplifier, ref<Expr> address, Expr::Width width, ObjectPair &result,
                        bool *inBounds);

public:
    /// ExecutionState that owns this AddressSpace
    ExecutionState *state;

protected:
    virtual void addressSpaceChange(const MemoryObject *mo, const ObjectState *oldState, ObjectState *newState);

private:
    /// Quick lookup of frequently-accessed objects
    ObjectCache m_cache;

public:
    AddressSpace(ExecutionState *_state) : AddressSpaceBase(), state(_state) {
    }
    AddressSpace(const AddressSpace &b) : AddressSpaceBase(b), state(NULL) {
    }
    virtual ~AddressSpace() {
    }

    void addCachedObject(const MemoryObject *mo, const ObjectState *os);
    void updateCachedObject(const MemoryObject *mo, const ObjectState *os);

    /// Resolve address to an ObjectPair in result.
    /// \return true iff an object was found.
    bool resolveOne(const ref<ConstantExpr> &address, ObjectPair &result);

    /// Resolve address to an ObjectPair in result.
    ///
    /// \param state The state this address space is part of.
    /// \param solver A solver used to determine possible
    ///               locations of the \a address.
    /// \param address The address to search for.
    /// \param[out] result An ObjectPair this address can resolve to
    ///               (when returning true).
    /// \return true iff an object was found at \a address.
    bool resolveOne(ExecutionState &state, TimingSolver *solver, ref<Expr> address, ObjectPair &result, bool &success);

    /// Resolve address to a list of ObjectPairs it can point to. If
    /// maxResolutions is non-zero then no more than that many pairs
    /// will be returned.
    ///
    /// \return true iff the resolution is incomplete (maxResolutions
    /// is non-zero and the search terminated early, or a query timed out).
    bool resolve(ExecutionState &state, TimingSolver *solver, ref<Expr> address, ResolutionList &rl,
                 unsigned maxResolutions = 0, double timeout = 0.);

    /***/

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
