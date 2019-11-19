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

void AddressSpace::bindObject(const ObjectStatePtr &os) {
    assert(os->getAddress() && os->getSize());

    auto oldOS = findObject(os->getAddress());

    if (oldOS) {
        addressSpaceChange(oldOS->getKey(), oldOS, nullptr);
    }

    addressSpaceChange(os->getKey(), nullptr, os);

    assert(os->getOwnerId() == 0 && "object already has owner");

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();
    os->setOwnerId(cowKey);
    objects = objects.replace(std::make_pair(key, os));
}

void AddressSpace::unbindObject(const ObjectStateConstPtr &os) {
    assert(os->getAddress() && os->getSize());
    auto oldOs = findObject(os->getAddress());
    assert(oldOs.get() == os.get());

    if (os) {
        addressSpaceChange(os->getKey(), os, nullptr);
    }

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();
    objects = objects.remove(key);
}

bool AddressSpace::findObject(uint64_t address, unsigned size, ObjectStateConstPtr &result, bool &inBounds) {
    auto res = findObject(address);
    if (!res) {
        return false;
    }

    assert(res->getAddress() <= address && res->getSize());

    result = res;

    inBounds = address + size <= res->getAddress() + res->getSize();
    return true;
}

void AddressSpace::updateWritable(const ObjectStateConstPtr &os, const ObjectStatePtr &wos) {
    wos->setOwnerId(cowKey);

    // XXX: should this come at the end?
    addressSpaceChange(os->getKey(), os, wos);

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();
    objects = objects.replace(std::make_pair(key, wos));
}

void AddressSpace::addressSpaceChange(const klee::ObjectKey &key, const ObjectStateConstPtr &oldState,
                                      const ObjectStatePtr &newState) {
    assert(state);
    state->addressSpaceChange(key, oldState, newState);
}

ObjectStatePtr AddressSpace::getWriteable(const ObjectStateConstPtr &os) {
    assert(!os->isReadOnly());

    if (isOwnedByUs(os)) {
        return ObjectStatePtr(const_cast<ObjectState *>(os.get()));
    }

    // Check whether we have a split object
    unsigned bits = os->getBitArraySize();
    if (bits == os->getSize()) {
        assert(os->getStoreOffset() == 0);
        return getWriteableInternal(os);
    }

    // Split objects are just like other objects, we may
    // need to get a private copy of them later on.
    assert(bits > os->getSize());

    // Find all the pieces and make them writable
    uint64_t address = os->getAddress() - os->getStoreOffset();
    ObjectStatePtr ret = nullptr;

    std::vector<ObjectStateConstPtr> readOnlyObjects;

    do {
        auto mo = findObject(address);
        assert(!isOwnedByUs(mo));

        readOnlyObjects.push_back(mo);
        address += mo->getSize();
        bits -= mo->getSize();
    } while (bits > 0);

    auto concreteBuffer = ConcreteBuffer::create(os->getConcreteBufferPtr());
    auto concreteMask = BitArray::create(os->getConcreteMask());
    assert(concreteMask->getBitCount() == concreteBuffer->size());

    for (unsigned i = 0; i < readOnlyObjects.size(); ++i) {
        auto &ros = readOnlyObjects[i];
        auto wos = ros->copy(concreteMask, concreteBuffer);

        if (ros == os) {
            ret = wos;
        }

        updateWritable(ros, wos);
    }

    assert(ret);
    return ret;
}

bool AddressSpace::splitMemoryObject(ExecutionState &state, const ObjectStateConstPtr &originalObject,
                                     ResolutionList &rl) {
    static const unsigned PAGE_SIZE = 0x1000;
    // Only split memory objects
    if (originalObject->getSize() != PAGE_SIZE || !originalObject->isSplittable()) {
        return false;
    }

    // The split must not affect any other state, therefore,
    // we need to get a private copy of the object
    auto originalWritableObject = getWriteable(originalObject);

    // When the entire object is concrete, it does not have
    // a concrete mask. For simplicity, we create one in case
    // of splitting.
    originalWritableObject->initializeConcreteMask();

    std::vector<ObjectStatePtr> objectStates;
    std::vector<unsigned> offsets;

    // XXX: for now, split into fixed-size objects
    for (unsigned i = 0; i < PAGE_SIZE / 128; ++i) {
        offsets.push_back(i * 128);
    }

    for (unsigned i = 0; i < offsets.size(); ++i) {
        auto offset = offsets[i];
        auto size = 128u;
        auto newObject = originalWritableObject->split(offset, size);
        objectStates.push_back(newObject);
        rl.push_back(newObject);
        offset += newObject->getSize();
        assert(size == newObject->getSize());
    }

    // Notify the system that the objects were split
    state.addressSpaceObjectSplit(originalObject, objectStates);

    // Once this is done, activate the new objects and delete the old one
    unbindObject(originalObject);

    for (auto it : objectStates) {
        bindObject(it);
    }

    return true;
}
}
