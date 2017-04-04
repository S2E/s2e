///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <iomanip>
#include <iostream>
#include <sstream>

#include "CacheProfiler.h"
#include "lib/BinaryReaders/Library.h"

using namespace s2e::plugins;

namespace s2etools {

// XXX: this should go to a statistics class
void Cache::print(std::ostream &os) {
    os << std::dec;
    os << "Cache " << m_name << " - Statistics" << std::endl;
    os << "Total Read  Misses: " << m_TotalMissesOnRead << std::endl;
    os << "Total Write Misses: " << m_TotalMissesOnWrite << std::endl;
    os << "Total       Misses: " << m_TotalMissesOnRead + m_TotalMissesOnWrite << std::endl;
}

CacheProfiler::CacheProfiler(ModuleCache *modCache, LogEvents *events) {
    m_moduleCache = modCache;
    m_Events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &CacheProfiler::onItem));
}

CacheProfiler::~CacheProfiler() {
    Caches::iterator it;
    m_connection.disconnect();
    for (it = m_caches.begin(); it != m_caches.end(); ++it) {
        delete (*it).second;
    }
}

void CacheProfiler::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    // std::cout << "Processing entry " << std::dec << traceIndex << " - " << (int)hdr.type << std::endl;

    if (hdr.type != s2e::plugins::TRACE_CACHESIM) {
        return;
    }

    ExecutionTraceCache *e = (ExecutionTraceCache *) item;

    if (e->type == s2e::plugins::CACHE_NAME) {
        std::string s((const char *) e->name.name, e->name.length);
        m_cacheIds[e->name.id] = s;
    } else if (e->type == s2e::plugins::CACHE_PARAMS) {
        CacheIdToName::iterator it = m_cacheIds.find(e->params.cacheId);
        assert(it != m_cacheIds.end());

        Cache *params = new Cache((*it).second, e->params.lineSize, e->params.size, e->params.associativity);

        m_caches[e->params.cacheId] = params;
        // XXX: fix that when needed
        // params->setUpperCache(NULL);
    } else if (e->type == s2e::plugins::CACHE_ENTRY) {
        const ExecutionTraceCacheSimEntry *se = &e->entry;

        CacheProfilerState *state =
            static_cast<CacheProfilerState *>(m_Events->getState(this, &CacheProfilerState::factory));
        state->processCacheItem(this, hdr.pid, se);
    } else {
        assert(false && "Unknown cache trace entry");
    }
}

void CacheProfiler::printAggregatedStatistics(std::ostream &os) const {
    Caches::const_iterator it;

    os << "Statistics for the entire recorded execution path" << std::endl;
    for (it = m_caches.begin(); it != m_caches.end(); ++it) {
        (*it).second->print(os);
        os << "-------------------------------------" << std::endl;
    }
}

void CacheProfiler::printAggregatedStatisticsHtml(std::ostream &os) const {
    Caches::const_iterator it;

    std::string title = "Statistics for the entire recorded execution path";

    os << "<TABLE BORDER=1 CELLPADDING=5>" << std::endl;
    os << "<TR><TH COLSPAN=4>" << title << "</TH></TR>" << std::endl;
    os << "<TR><TD>Cache</TD><TD>Read</TD><TD>Write</TD><TD>Total</TD></TR>" << std::endl;

    for (it = m_caches.begin(); it != m_caches.end(); ++it) {
        const Cache *c = (*it).second;
        CacheStatistics s;
        s.readMissCount = c->getTotalReadMisses();
        s.writeMissCount = c->getTotalWriteMisses();
        s.c = const_cast<Cache *>(c);

        s.printHtml(os);
    }

    os << "</TABLE>" << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

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

void CacheProfilerState::processCacheItem(CacheProfiler *cp, uint64_t pid, const ExecutionTraceCacheSimEntry *e) {
    Caches::iterator it = cp->m_caches.find(e->cacheId);
    assert(it != cp->m_caches.end());

    Cache *c = (*it).second;
    assert(c);

    if (e->missCount > 0) {
        if (e->isWrite) {
            c->m_TotalMissesOnWrite += e->missCount;
        } else {
            c->m_TotalMissesOnRead += e->missCount;
        }
    }

    // Update the per-instruction statistics
    ModuleCacheState *mcs =
        static_cast<ModuleCacheState *>(cp->m_Events->getState(cp->m_moduleCache, &ModuleCacheState::factory));
    assert(mcs);

    InstructionCacheStatistics s;
    const ModuleInstance *modInst = mcs->getInstance(pid, e->pc);
    s.instr.m = modInst;
    s.instr.loadBase = modInst ? modInst->LoadBase : 0;
    s.instr.pid = pid;
    s.instr.pc = e->pc;
    s.stats.c = c;

    if (e->isWrite) {
        s.stats.writeMissCount = e->missCount;
    } else {
        s.stats.readMissCount = e->missCount;
    }

    // Update the per-instruction statistics
    CacheStatisticsMap::iterator cssit = m_statistics.find(std::make_pair(s.instr, c));
    if (cssit == m_statistics.end()) {
        m_statistics[std::make_pair(s.instr, c)] = s.stats;
    } else {
        assert((*cssit).first.first.pid == pid && (*cssit).first.first.pc == e->pc);
        if (e->isWrite) {
            (*cssit).second.writeMissCount += e->missCount;
        } else {
            (*cssit).second.readMissCount += e->missCount;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void CacheStatistics::printHtml(std::ostream &os) const {

    os << "<TR><TD>" << c->getName() << "</TD><TD>" << readMissCount << "</TD><TD>" << writeMissCount << "</TD><TD>"
       << (readMissCount + writeMissCount) << "</TD></TR>" << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

TopMissesPerModule::TopMissesPerModule(Library *library, CacheProfiler *prof) {
    m_Profiler = prof;
    m_displayAllModules = true;
    m_library = library;
    m_totalMisses = 0;
}

TopMissesPerModule::~TopMissesPerModule() {
}

void TopMissesPerModule::computeStats(uint32_t pathId) {
    CacheProfilerState *state =
        static_cast<CacheProfilerState *>(m_Profiler->getEvents()->getState(m_Profiler, pathId));
    if (!state) {
        return;
    }

    const CacheStatisticsMap &stats = state->getStats();
    CacheStatisticsMap::const_iterator it;

    uint64_t filteredPid = 0;
    if (m_filteredProcess.size() > 0) {
        // look for the right process id
        for (it = stats.begin(); it != stats.end(); ++it) {
            if ((*it).first.first.m && (*it).first.first.m->Name == m_filteredProcess) {
                filteredPid = (*it).first.first.pid;
                break;
            }
        }
    }

    // Sort all the elements by total misses
    for (it = stats.begin(); it != stats.end(); ++it) {
        InstructionCacheStatistics ex;
        ex.instr = (*it).first.first;
        ex.stats = (*it).second;
        // std::cout << ex.stats.c->getName();

        if (m_filteredModule.size() > 0) {
            if ((*it).first.first.m && (*it).first.first.m->Name != m_filteredModule) {
                continue;
            }
        }

        if (!filteredPid || filteredPid == ex.instr.pid) {
            m_stats.insert(ex);
            m_totalMisses += ex.stats.readMissCount + ex.stats.writeMissCount;
        }
    }
}

void TopMissesPerModule::printAggregatedStatistics(std::ostream &os) const {
    std::map<Cache *, CacheStatistics> cacheStats;

    std::stringstream title;
    if (m_filteredProcess.size() > 0) {
        title << "Statistics for cache misses in the address space of " << m_filteredProcess << std::endl;
    } else {
        title << "Statistics for the entire recorded execution path" << std::endl;
    }

    TopMissesPerModuleSet::const_reverse_iterator sit;
    for (sit = m_stats.rbegin(); sit != m_stats.rend(); ++sit) {
        const InstructionCacheStatistics &s = (*sit);
        assert(s.stats.c);

        std::map<Cache *, CacheStatistics>::iterator it = cacheStats.find(s.stats.c);
        if (it == cacheStats.end()) {
            cacheStats[s.stats.c] = s.stats;
        } else {
            (*it).second += s.stats;
        }
    }

    std::map<Cache *, CacheStatistics>::iterator it;
    for (it = cacheStats.begin(); it != cacheStats.end(); ++it) {
        const Cache *c = (*it).first;

        os << "------   -------------------------------" << std::endl;

        os << std::dec;
        os << "Cache " << c->getName() << " - Statistics" << std::endl;
        os << "Total Read  Misses: " << (*it).second.readMissCount << std::endl;
        os << "Total Write Misses: " << (*it).second.writeMissCount << std::endl;
        os << "Total       Misses: " << (*it).second.readMissCount + (*it).second.writeMissCount << std::endl;
    }
}

void TopMissesPerModule::print(std::ostream &os) {
    TopMissesPerModuleSet::const_reverse_iterator sit;
    os << std::setw(15) << std::left << "Module" << std::setw(10) << " PC" << std::setw(6) << "       ReadMissCount"
       << std::setw(6) << " WriteMissCount" << std::endl;

    for (sit = m_stats.rbegin(); sit != m_stats.rend(); ++sit) {
        const InstructionCacheStatistics &s = (*sit);
        if (s.stats.readMissCount + s.stats.writeMissCount < m_minCacheMissThreshold) {
            continue;
        }

        std::string modName = s.instr.m ? s.instr.m->Name : "<unknown>";
        os << std::setw(15) << modName << std::hex << " 0x" << std::setw(8) << s.instr.pc << " - ";
        // os << std::hex << std::right << std::setfill('0') << "0x" << std::setw(8) << s.instr.pid
        //                                    << " 0x" << std::setw(8) << s.instr.pc << " - ";
        os << std::setfill(' ');
        os << s.stats.c->getName() << " ";
        os << std::dec << std::setw(13) << s.stats.readMissCount << " " << std::setw(14) << s.stats.writeMissCount;

        if (s.instr.m) {
            std::string dbg;
            if (m_library->print(modName, s.instr.loadBase, s.instr.m->ImageBase, s.instr.pc, dbg, true, true, true)) {
                os << " - " << dbg;
            }
        }
        os << std::endl;
    }
}
}
