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

#ifndef ADDRESS_SPACE_CACHE_H

#define ADDRESS_SPACE_CACHE_H

#include <inttypes.h>
#include <klee/AddressSpace.h>
#include <klee/Memory.h>
#include "MemoryCache.h"
#include "s2e_config.h"

namespace s2e {

class AddressSpaceCache {
public:
    typedef MemoryCachePool<klee::ObjectStateConstPtr, SE_RAM_OBJECT_BITS,
                            12, // XXX: FIX THIS HARD-CODED STUFF!
                            S2E_MEMCACHE_SUPERPAGE_BITS>
        S2EMemoryCache;

private:
    klee::AddressSpace *m_addressSpace;
    mutable S2EMemoryCache m_memcache;

public:
    AddressSpaceCache(klee::AddressSpace *as) : m_addressSpace(as) {
    }

    void update(klee::AddressSpace *as) {
        m_addressSpace = as;
    }

    void invalidate(uintptr_t page_addr) {
        assert((page_addr & ~SE_RAM_OBJECT_MASK) == 0);
        m_memcache.put(page_addr, nullptr);
    }

    void registerPool(uintptr_t hostAddress, uintptr_t size) {
        m_memcache.registerPool(hostAddress, size);
    }

    klee::ObjectStateConstPtr get(uintptr_t page_addr);

    klee::ObjectStatePtr getBaseObject(const klee::ObjectStatePtr &object);

    klee::ObjectStatePtr notifySplit(const klee::ObjectStateConstPtr &oldObject,
                                     const std::vector<klee::ObjectStatePtr> &newObjects);

    inline bool isOwnedByUs(const klee::ObjectStateConstPtr &os) {
        return m_addressSpace->isOwnedByUs(os);
    }
};
} // namespace s2e

#endif
