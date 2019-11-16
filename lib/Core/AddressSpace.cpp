//===-- AddressSpace.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/AddressSpace.h"
#include "klee/ExecutionState.h"
#include "klee/Memory.h"

namespace klee {

void AddressSpace::bindObject(const MemoryObject *mo, ObjectState *os) {
    assert(mo->address && mo->size);
    const ObjectState *oldOS = findObject(mo);

    if (oldOS) {
        addressSpaceChange(mo, oldOS, nullptr);
    }

    addressSpaceChange(mo, nullptr, os);

    assert(os->copyOnWriteOwner == 0 && "object already has owner");

    os->copyOnWriteOwner = cowKey;
    objects = objects.replace(std::make_pair(mo, os));
}

void AddressSpace::unbindObject(const MemoryObject *mo) {
    assert(mo->address && mo->size);
    const ObjectState *os = findObject(mo);

    if (os) {
        addressSpaceChange(mo, os, nullptr);
    }

    objects = objects.remove(mo);
}

bool AddressSpace::findObject(uint64_t address, unsigned size, ObjectPair &result, bool &inBounds) {
    MemoryObject hack(address);
    hack.size = 1;

    auto res = objects.lookup(&hack);
    if (!res) {
        return false;
    }

    assert(res->first->address <= address && res->first->size);

    result = *res;

    auto mo = res->first;
    inBounds = address + size <= mo->address + mo->size;
    return true;
}

void AddressSpace::updateWritable(const MemoryObject *mo, const ObjectState *os, ObjectState *wos) {
    wos->copyOnWriteOwner = cowKey;

    addressSpaceChange(mo, os, wos);

    objects = objects.replace(std::make_pair(mo, wos));
}

void AddressSpace::addressSpaceChange(const MemoryObject *mo, const ObjectState *oldState, ObjectState *newState) {
    assert(state);
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

    // Split objects are just like other objects, we may
    // need to get a private copy of them later on.
    assert(bits > mo->size);

    // Find all the pieces and make them writable
    uint64_t address = mo->address - os->getStoreOffset();
    ObjectState *ret = nullptr;

    std::vector<const ObjectState *> readOnlyObjects;

    do {
        ObjectPair pair = findObject(address);
        assert(pair.first && pair.second);

        assert(!isOwnedByUs(pair.second));

        readOnlyObjects.push_back(pair.second);
        address += mo->size;
        bits -= mo->size;
    } while (bits > 0);

    auto concreteBuffer = ConcreteBuffer::create(os->getConcreteBuffer());
    auto concreteMask = BitArray::create(os->getConcreteMask());
    assert(concreteMask->getBitCount() == concreteBuffer->size());

    for (unsigned i = 0; i < readOnlyObjects.size(); ++i) {
        const ObjectState *ros = readOnlyObjects[i];
        ObjectState *wos = ros->getCopy(concreteMask, concreteBuffer);

        if (ros == os) {
            ret = wos;
        }

        updateWritable(ros->getObject(), ros, wos);
    }

    assert(ret);
    return ret;
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

bool MemoryObjectLTS::operator()(const MemoryObject *a, const MemoryObject *b) const {
    return a->address + a->size <= b->address;
}
}
