///
/// Copyright (C) 2012, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    typedef MemoryCachePool<klee::ObjectPair, SE_RAM_OBJECT_BITS,
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
        m_memcache.put(page_addr, klee::ObjectPair(NULL, NULL));
    }

    void registerPool(uintptr_t hostAddress, uintptr_t size) {
        m_memcache.registerPool(hostAddress, size);
    }

    klee::ObjectPair get(uintptr_t page_addr);

    klee::ObjectState *getBaseObject(klee::ObjectState *object);

    klee::ObjectState *notifySplit(const klee::ObjectState *oldObject,
                                   const std::vector<klee::ObjectState *> &newObjects);

    inline bool isOwnedByUs(const klee::ObjectState *os) {
        return m_addressSpace->isOwnedByUs(os);
    }
};
}

#endif
