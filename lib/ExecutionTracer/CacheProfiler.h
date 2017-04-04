///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_CACHEPROFILERLIB_H
#define S2ETOOLS_CACHEPROFILERLIB_H

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include "LogParser.h"

namespace s2etools {

class Cache;
class CacheProfilerState;

class CacheProfiler {
public:
    typedef std::map<uint32_t, Cache *> Caches;
    typedef std::map<uint32_t, std::string> CacheIdToName;

private:
    sigc::connection m_connection;
    LogEvents *m_events;

    Caches m_caches;
    CacheIdToName m_cacheIds;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    CacheProfiler(LogEvents *events);

    ~CacheProfiler();

    friend class CacheProfilerState;
};

struct CacheStatistics {
    Cache *c;
    uint64_t readMissCount;
    uint64_t writeMissCount;

    CacheStatistics() {
        c = NULL;
        readMissCount = writeMissCount = 0;
    }

    CacheStatistics(uint64_t rmiss, uint64_t wmiss) {
        c = NULL;
        readMissCount = rmiss;
        writeMissCount = wmiss;
    }

    CacheStatistics operator+(const CacheStatistics &r) {
        CacheStatistics ret;
        ret.readMissCount = readMissCount + r.readMissCount;
        ret.writeMissCount = writeMissCount + r.writeMissCount;
        return ret;
    }

    CacheStatistics &operator+=(const CacheStatistics &r) {
        readMissCount += r.readMissCount;
        writeMissCount += r.writeMissCount;
        return *this;
    }
};

class CacheProfilerState : public ItemProcessorState {
public:
    typedef std::map<Cache *, CacheStatistics> CacheStats;
    typedef std::pair<uint64_t, uint64_t> Instruction; //(pc,pid)
    typedef std::map<Instruction, CacheStats> InstructionCacheStats;

    InstructionCacheStats m_perInstructionStats;
    CacheStats m_cacheStats;
    CacheStatistics m_globalStats;

public:
    CacheProfilerState();
    virtual ~CacheProfilerState();

    static ItemProcessorState *factory();
    virtual ItemProcessorState *clone() const;

    void processCacheItem(CacheProfiler *cp, const s2e::plugins::ExecutionTraceItemHeader &hdr,
                          const s2e::plugins::ExecutionTraceCacheSimEntry &e);

    friend class CacheProfiler;
};

/////////////////////////////////////

class Cache {
private:
    unsigned m_size;
    unsigned m_lineSize;
    unsigned m_associativity;
    std::string m_name;
    Cache *m_upper;

public:
    Cache(const std::string &name, unsigned lineSize, unsigned size, unsigned assoc) {
        m_size = size;
        m_lineSize = lineSize;
        m_associativity = assoc;
        m_name = name;
        m_upper = NULL;
    }

    void setUpperCache(Cache *p) {
        m_upper = p;
    }

    void print(std::ostream &os);

    std::string getName() const {
        return m_name;
    }
};
}
#endif
