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

klee::ObjectStateConstPtr AddressSpaceCache::get(uintptr_t page_addr) {
    assert((page_addr & ~SE_RAM_OBJECT_MASK) == 0);

    auto os = m_memcache.get(page_addr);
    if (!os) {
        os = m_addressSpace->findObject(page_addr);
        m_memcache.put(page_addr, os);
    }

    /* We are guaranteed to have a memory object that starts
       on a page boundary */
    assert(os && os->getAddress() == page_addr);

    return os;
}

klee::ObjectStatePtr AddressSpaceCache::getBaseObject(const klee::ObjectStatePtr &object) {
    uint64_t hostAddress = object->getAddress();
    uint64_t offset = object->getStoreOffset();

    if (offset) {
        hostAddress -= offset;
        auto os = m_memcache.get(hostAddress);
        if (!os) {
            os = m_addressSpace->findObject(hostAddress);
            assert(os);
            m_memcache.put(hostAddress, os);
        }
        // XXX: do we need a writable one?
        return m_addressSpace->getWriteable(os);
    }

    return object;
}

klee::ObjectStatePtr AddressSpaceCache::notifySplit(const klee::ObjectStateConstPtr &oldObject,
                                                    const std::vector<klee::ObjectStatePtr> &newObjects) {
    assert(oldObject->isSplittable() && oldObject->getSize() == TARGET_PAGE_SIZE);
    assert(newObjects.size() == SE_RAM_OBJECT_SIZE / S2E_RAM_SUBOBJECT_SIZE);

    ObjectStatePtr baseObject = nullptr;
    for (unsigned i = 0; i < newObjects.size(); ++i) {
        auto &obj = newObjects[i];
        if (obj->getStoreOffset() == 0) {
            baseObject = obj;
            break;
        }
    }

    assert(baseObject);
    invalidate(oldObject->getAddress());

    return baseObject;
}
} // namespace s2e
