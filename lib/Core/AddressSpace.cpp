//===-- AddressSpace.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/AddressSpace.h"
#include "klee/CoreStats.h"
#include "klee/Memory.h"
#include "TimingSolver.h"

#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/TimerStatIncrementer.h"

using namespace klee;

/**
 * Clients can set this to true if the want the address of the
 * the cloned object to be the same as the RO one.
 */
namespace klee {
bool g_klee_address_space_preserve_concrete_buffer_address = false;
}

///

template <typename LT>
void AddressSpaceBase<LT>::updateWritable(const MemoryObject *mo, const ObjectState *os, ObjectState *wos) {
    wos->copyOnWriteOwner = cowKey;

    addressSpaceChange(mo, os, wos);

    objects = objects.replace(std::make_pair(mo, wos));
}

///

void AddressSpace::addressSpaceChange(const MemoryObject *mo, const ObjectState *oldState, ObjectState *newState) {
    assert(state);
    updateCachedObject(mo, newState);
    state->addressSpaceChange(mo, oldState, newState);
}

ObjectState *AddressSpace::getWriteable(const MemoryObject *mo, const ObjectState *os) {
    assert(!os->readOnly);

    if (isOwnedByUs(os)) {
        return const_cast<ObjectState *>(os);
    }

    // Check whether we have a split object
    unsigned bits = os->getBitArraySize();
    if (bits == mo->size) {
        assert(os->getStoreOffset() == 0);
        return getWriteableInternal(mo, os);
    }

    assert(!g_klee_address_space_preserve_concrete_buffer_address &&
           "Implement in place concrete buffer swap (see getWritableInternal)");

    // Split objects are just like other objects, we may
    // need to get a private copy of them later on.
    assert(bits > mo->size);

    // Find all the pieces and make them writable
    uint64_t address = mo->address - os->getStoreOffset();
    ObjectState *ret = NULL;

    std::vector<const ObjectState *> readOnlyObjects;

    do {
        ObjectPair pair = findObject(address);
        assert(pair.first && pair.second);

        assert(!isOwnedByUs(pair.second));

        readOnlyObjects.push_back(pair.second);
        address += mo->size;
        bits -= mo->size;
    } while (bits > 0);

    ConcreteBuffer *concreteBuffer = new ConcreteBuffer(*os->getConcreteBuffer());
    BitArray *concreteMask = new BitArray(*os->getConcreteMask(), concreteBuffer->getSize());

    for (unsigned i = 0; i < readOnlyObjects.size(); ++i) {
        const ObjectState *ros = readOnlyObjects[i];
        ObjectState *wos = ros->getCopy(concreteMask, concreteBuffer);

        if (ros == os) {
            ret = wos;
        }

        updateWritable(ros->getObject(), ros, wos);
    }

    concreteBuffer->decref();
    concreteMask->decref();

    assert(ret);
    return ret;
}

///

void AddressSpace::addCachedObject(const MemoryObject *mo, const ObjectState *os) {
    for (unsigned i = 0; i < m_cache.size(); ++i) {
        if (m_cache[i].first == mo) {
            if (os) {
                m_cache[i].second = os;
            }
            return;
        }
    }

    os = findObject(mo);
    if (os) {
        m_cache.push_back(ObjectPair(mo, os));
    }
}

void AddressSpace::updateCachedObject(const MemoryObject *mo, const ObjectState *os) {
    for (unsigned i = 0; i < m_cache.size(); ++i) {
        if (m_cache[i].first == mo) {
            if (os) {
                m_cache[i].second = os;
            }
            return;
        }
    }
}

bool AddressSpace::resolveOne(const ref<ConstantExpr> &addr, ObjectPair &result) {
    uint64_t address = addr->getZExtValue();

    for (unsigned i = 0; i < m_cache.size(); ++i) {
        const MemoryObject *mo = m_cache[i].first;
        if ((mo->size == 0 && address == mo->address) || (address - mo->address < mo->size)) {
            result = m_cache[i];
            return true;
        }
    }

    MemoryObject hack(address);

    if (const MemoryMap::value_type *res = objects.lookup_previous(&hack)) {
        const MemoryObject *mo = res->first;
        if ((mo->size == 0 && address == mo->address) || (address - mo->address < mo->size)) {
            result = *res;
            return true;
        }
    }

    return false;
}

bool AddressSpace::resolveOneFast(BitfieldSimplifier &simplifier, ref<Expr> address, Expr::Width width,
                                  ObjectPair &result, bool *inBounds) {
    if (isa<ConstantExpr>(address)) {
        ref<ConstantExpr> ce = dyn_cast<ConstantExpr>(address);
        bool success = resolveOne(ce, result);
        if (!success) {
            return false;
        }

        assert(ce->getZExtValue() >= result.first->address);
        uintptr_t val = ce->getZExtValue() - result.first->address;
        if (val + Expr::getMinBytesForWidth(width) <= result.first->size) {
            *inBounds = true;
        } else {
            *inBounds = false;
        }

        return true;
    }

    ref<AddExpr> add = dyn_cast<AddExpr>(address);
    if (add.isNull()) {
        return false;
    }

    ref<ConstantExpr> base = dyn_cast<ConstantExpr>(add->getLeft());
    if (base.isNull()) {
        return false;
    }

    ref<Expr> offset = add->getRight();
    uint64_t knownZeroBits;
    simplifier.simplify(offset, &knownZeroBits);

    uint64_t inBoundsSize;
    // Only handle 8-bits sized objects for now.
    // TODO: make it work for arbitrary consecutive numbers of 1s.
    if ((knownZeroBits & ~(uint64_t) 0xff) == ~(uint64_t) 0xff) {
        inBoundsSize = 1 << 8;
    } else {
        return false;
    }

    bool success = resolveOne(base, result);
    if (!success) {
        return false;
    }

    if (result.first->address != base->getZExtValue()) {
        return false;
    }

    if (result.first->size <= inBoundsSize) {
        *inBounds = true;
    } else {
        *inBounds = false;
    }

    return true;
}

bool AddressSpace::resolveOne(ExecutionState &state, TimingSolver *solver, ref<Expr> address, ObjectPair &result,
                              bool &success) {
    if (isa<ConstantExpr>(address)) {
        ref<ConstantExpr> CE = dyn_cast<ConstantExpr>(address);
        success = resolveOne(CE, result);
        return true;
    } else {
        TimerStatIncrementer timer(stats::resolveTime);

        // try cheap search, will succeed for any inbounds pointer

        ref<ConstantExpr> cex;
        if (!solver->getValue(state, address, cex))
            return false;
        uint64_t example = cex->getZExtValue();
        MemoryObject hack(example);
        const MemoryMap::value_type *res = objects.lookup_previous(&hack);

        if (res) {
            const MemoryObject *mo = res->first;
            if (example - mo->address < mo->size) {
                result = *res;
                success = true;
                return true;
            }
        }

        // didn't work, now we have to search

        MemoryMap::iterator oi = objects.upper_bound(&hack);
        MemoryMap::iterator begin = objects.begin();
        MemoryMap::iterator end = objects.end();

        MemoryMap::iterator start = oi;
        while (oi != begin) {
            --oi;
            const MemoryObject *mo = oi->first;

            bool mayBeTrue;
            if (!solver->mayBeTrue(state, mo->getBoundsCheckPointer(address), mayBeTrue))
                return false;
            if (mayBeTrue) {
                result = *oi;
                success = true;
                return true;
            } else {
                bool mustBeTrue;
                if (!solver->mustBeTrue(state, UgeExpr::create(address, mo->getBaseExpr()), mustBeTrue))
                    return false;
                if (mustBeTrue)
                    break;
            }
        }

        // search forwards
        for (oi = start; oi != end; ++oi) {
            const MemoryObject *mo = oi->first;

            bool mustBeTrue;
            if (!solver->mustBeTrue(state, UltExpr::create(address, mo->getBaseExpr()), mustBeTrue))
                return false;
            if (mustBeTrue) {
                break;
            } else {
                bool mayBeTrue;

                if (!solver->mayBeTrue(state, mo->getBoundsCheckPointer(address), mayBeTrue))
                    return false;
                if (mayBeTrue) {
                    result = *oi;
                    success = true;
                    return true;
                }
            }
        }

        success = false;
        return true;
    }
}

bool AddressSpace::resolve(ExecutionState &state, TimingSolver *solver, ref<Expr> p, ResolutionList &rl,
                           unsigned maxResolutions, double timeout) {
    if (isa<ConstantExpr>(p)) {
        ref<ConstantExpr> CE = dyn_cast<ConstantExpr>(p);
        ObjectPair res;
        if (resolveOne(CE, res))
            rl.push_back(res);
        return false;
    } else {
        TimerStatIncrementer timer(stats::resolveTime);
        uint64_t timeout_us = (uint64_t)(timeout * 1000000.);

        // XXX in general this isn't exactly what we want... for
        // a multiple resolution case (or for example, a \in {b,c,0})
        // we want to find the first object, find a cex assuming
        // not the first, find a cex assuming not the second...
        // etc.

        // XXX how do we smartly amortize the cost of checking to
        // see if we need to keep searching up/down, in bad cases?
        // maybe we don't care?

        // XXX we really just need a smart place to start (although
        // if its a known solution then the code below is guaranteed
        // to hit the fast path with exactly 2 queries). we could also
        // just get this by inspection of the expr.

        ref<ConstantExpr> cex;
        if (!solver->getValue(state, p, cex))
            return true;
        uint64_t example = cex->getZExtValue();
        MemoryObject hack(example);

        MemoryMap::iterator oi = objects.upper_bound(&hack);
        MemoryMap::iterator begin = objects.begin();
        MemoryMap::iterator end = objects.end();

        MemoryMap::iterator start = oi;

        // XXX in the common case we can save one query if we ask
        // mustBeTrue before mayBeTrue for the first result. easy
        // to add I just want to have a nice symbolic test case first.

        // search backwards, start with one minus because this
        // is the object that p *should* be within, which means we
        // get write off the end with 4 queries (XXX can be better,
        // no?)
        while (oi != begin) {
            --oi;
            const MemoryObject *mo = oi->first;
            if (timeout_us && timeout_us < timer.check())
                return true;

            // XXX I think there is some query wasteage here?
            ref<Expr> inBounds = mo->getBoundsCheckPointer(p);
            bool mayBeTrue;
            if (!solver->mayBeTrue(state, inBounds, mayBeTrue))
                return true;
            if (mayBeTrue) {
                rl.push_back(*oi);

                // fast path check
                unsigned size = rl.size();
                if (size == 1) {
                    bool mustBeTrue;
                    if (!solver->mustBeTrue(state, inBounds, mustBeTrue))
                        return true;
                    if (mustBeTrue)
                        return false;
                } else if (size == maxResolutions) {
                    return true;
                }
            }

            bool mustBeTrue;
            if (!solver->mustBeTrue(state, UgeExpr::create(p, mo->getBaseExpr()), mustBeTrue))
                return true;
            if (mustBeTrue)
                break;
        }
        // search forwards
        for (oi = start; oi != end; ++oi) {
            const MemoryObject *mo = oi->first;
            if (timeout_us && timeout_us < timer.check())
                return true;

            bool mustBeTrue;
            if (!solver->mustBeTrue(state, UltExpr::create(p, mo->getBaseExpr()), mustBeTrue))
                return true;
            if (mustBeTrue)
                break;

            // XXX I think there is some query wasteage here?
            ref<Expr> inBounds = mo->getBoundsCheckPointer(p);
            bool mayBeTrue;
            if (!solver->mayBeTrue(state, inBounds, mayBeTrue))
                return true;
            if (mayBeTrue) {
                rl.push_back(*oi);

                // fast path check
                unsigned size = rl.size();
                if (size == 1) {
                    bool mustBeTrue;
                    if (!solver->mustBeTrue(state, inBounds, mustBeTrue))
                        return true;
                    if (mustBeTrue)
                        return false;
                } else if (size == maxResolutions) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool AddressSpace::splitMemoryObject(ExecutionState &state, const MemoryObject *originalObject, ResolutionList &rl) {
    static const unsigned PAGE_SIZE = 0x1000;
    // Only split memory objects
    if (originalObject->size != PAGE_SIZE || !originalObject->isSplittable) {
        return false;
    }

    const ObjectState *originalRoState = findObject(originalObject);
    if (!originalRoState) {
        return false;
    }

    // The split must not affect any other state, therefore,
    // we need to get a private copy of the object
    ObjectState *originalState = getWriteable(originalObject, originalRoState);

    // When the entire object is concrete, it does not have
    // a concrete mask. For simplicity, we create one in case
    // of splitting.
    originalState->initializeConcreteMask();

    ObjectHolder holder(originalState);

    std::vector<MemoryObject *> memoryObjects;
    std::vector<ObjectState *> objectStates;
    std::vector<unsigned> offsets;

    // XXX: for now, split into fixed-size objects
    for (unsigned i = 0; i < PAGE_SIZE / 128; ++i) {
        offsets.push_back(i * 128);
    }

    originalObject->split(memoryObjects, offsets);

    unsigned offset = 0;
    for (unsigned i = 0; i < memoryObjects.size(); ++i) {
        MemoryObject *memoryObject = memoryObjects[i];
        ObjectState *newObject = originalState->split(memoryObject, offset);
        objectStates.push_back(newObject);
        rl.push_back(std::make_pair(memoryObject, newObject));
        offset += memoryObject->size;
    }

    // Notify the system that the objects were split
    state.addressSpaceObjectSplit(originalState, objectStates);

    // Once this is done, activate the new objects and delete the old one
    unbindObject(originalObject);

    for (unsigned i = 0; i < memoryObjects.size(); ++i) {
        MemoryObject *memoryObject = memoryObjects[i];
        ObjectState *newObject = objectStates[i];
        bindObject(memoryObject, newObject);
    }

    // XXX: leaking objects. Should delete them from the memory manager
    // delete originalObject;

    return true;
}

/***/

bool MemoryObjectLT::operator()(const MemoryObject *a, const MemoryObject *b) const {
    return a->address < b->address;
}

bool MemoryObjectLTS::operator()(const MemoryObject *a, const MemoryObject *b) const {
    return a->address + a->size <= b->address;
}
