///
/// Copyright (C) 2012, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
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
