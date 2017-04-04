///
/// Copyright (C) 2012, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/AddressSpaceCache.h>
#include <s2e/cpu.h>

using namespace klee;

namespace s2e {

klee::ObjectPair AddressSpaceCache::get(uintptr_t page_addr) {
    assert((page_addr & ~SE_RAM_OBJECT_MASK) == 0);

    ObjectPair op = m_memcache.get(page_addr);
    if (!op.first) {
        op = m_addressSpace->findObject(page_addr);
        m_memcache.put(page_addr, op);
    }

    /* We are guaranteed to have a memory object that starts
       on a page boundary */
    assert(op.first && op.first->isUserSpecified && op.first->address == page_addr);

    return op;
}

ObjectState *AddressSpaceCache::getBaseObject(ObjectState *object) {
    uint64_t hostAddress = object->getObject()->address;
    uint64_t offset = object->getStoreOffset();
    if (offset) {
        hostAddress -= offset;
        ObjectPair op = m_memcache.get(hostAddress);
        if (!op.first) {
            op = m_addressSpace->findObject(hostAddress);
            assert(op.first && op.second);
            m_memcache.put(hostAddress, op);
        }
        // XXX: do we need a writable one?
        object = m_addressSpace->getWriteable(op.first, op.second);
    }
    return object;
}

klee::ObjectState *AddressSpaceCache::notifySplit(const klee::ObjectState *oldObject,
                                                  const std::vector<klee::ObjectState *> &newObjects) {
    const MemoryObject *oldMemoryObject = oldObject->getObject();
    assert(oldMemoryObject->isSplittable && oldMemoryObject->size == TARGET_PAGE_SIZE);
    assert(newObjects.size() == SE_RAM_OBJECT_SIZE / S2E_RAM_SUBOBJECT_SIZE);

    klee::ObjectState *baseObject = NULL;
    for (unsigned i = 0; i < newObjects.size(); ++i) {
        ObjectState *obj = newObjects[i];
        if (obj->getStoreOffset() == 0) {
            baseObject = obj;
            break;
        }
    }

    assert(baseObject);
    invalidate(oldMemoryObject->address);

    return baseObject;
}
}
