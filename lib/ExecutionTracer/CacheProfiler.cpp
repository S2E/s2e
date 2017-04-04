///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "CacheProfiler.h"
#include <cassert>
#include <iomanip>
#include <iostream>

using namespace s2e::plugins;

namespace s2etools {

CacheProfiler::CacheProfiler(LogEvents *events) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &CacheProfiler::onItem));
}

CacheProfiler::~CacheProfiler() {
    m_connection.disconnect();
}

void CacheProfiler::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type != s2e::plugins::TRACE_CACHESIM) {
        return;
    }

    ExecutionTraceCache *cacheItem = (ExecutionTraceCache *) item;

    switch (cacheItem->type) {

        // Save the name of the cache and the associated id.
        // Actual parameters will come later in the trace
        case s2e::plugins::CACHE_NAME: {
            std::string s((const char *) cacheItem->name.name, cacheItem->name.length);
            m_cacheIds[cacheItem->name.id] = s;
        } break;

        // Create the cache according to the parameters
        // in the trace
        case s2e::plugins::CACHE_PARAMS: {
            CacheIdToName::iterator it = m_cacheIds.find(cacheItem->params.cacheId);
            assert(it != m_cacheIds.end());

            Cache *params = new Cache((*it).second, cacheItem->params.lineSize, cacheItem->params.size,
                                      cacheItem->params.associativity);

            assert(m_caches.find(cacheItem->params.cacheId) == m_caches.end());
            m_caches[cacheItem->params.cacheId] = params;
            // XXX: fix that when needed
            // params->setUpperCache(NULL);
        } break;

        case s2e::plugins::CACHE_ENTRY: {
            const ExecutionTraceCacheSimEntry *se = &cacheItem->entry;

            CacheProfilerState *state =
                static_cast<CacheProfilerState *>(m_events->getState(this, &CacheProfilerState::factory));
            state->processCacheItem(this, hdr, *se);
        } break;

        default: { assert(false && "Unknown cache trace entry"); }
    }
}

///////////////////////////////////////////////////////////
ItemProcessorState *CacheProfilerState::factory() {
    return new CacheProfilerState();
}

CacheProfilerState::CacheProfilerState() {
}

CacheProfilerState::~CacheProfilerState() {
}

ItemProcessorState *CacheProfilerState::clone() const {
    return new CacheProfilerState(*this);
}

void CacheProfilerState::processCacheItem(CacheProfiler *cp, const s2e::plugins::ExecutionTraceItemHeader &hdr,
                                          const s2e::plugins::ExecutionTraceCacheSimEntry &e) {
    CacheProfiler::Caches::iterator it = cp->m_caches.find(e.cacheId);
    assert(it != cp->m_caches.end());
    assert((*it).second);
    (void) it;

    CacheStatistics addend(e.isWrite ? 0 : e.missCount, e.isWrite ? e.missCount : 0);

    m_globalStats += addend;

#if 0
    //Update the per-state global miss-rate count for the cache
    CacheStatistics &perCache = m_cacheStats[c];

    perCache += addend;
    perCache.c = c;

    //Update per-instruction misses
    CacheStats &instrStats = m_perInstructionStats[std::make_pair(hdr.pid, e.pc)];
    CacheStatistics &instrPerCache = instrStats[c];
    instrPerCache += addend;
    instrPerCache.c = c;
#endif
}
}
