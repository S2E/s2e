///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MemoryMap_H
#define S2E_PLUGINS_MemoryMap_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/IntervalMap.h>

namespace s2e {
namespace plugins {

typedef unsigned MemoryMapRegionType;
static const unsigned MM_NONE = 0;
static const unsigned MM_READ = 1;
static const unsigned MM_WRITE = 2;
static const unsigned MM_EXEC = 4;

class MemoryMap : public Plugin {
    S2E_PLUGIN
public:
    MemoryMap(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void trackPid(S2EExecutionState *state, uint64_t pid, bool track = true);
    MemoryMapRegionType getType(S2EExecutionState *state, uint64_t pid, uint64_t address) const;
    void addRegion(S2EExecutionState *state, uint64_t pid, uint64_t address, uint64_t end, MemoryMapRegionType type);

    void dump(S2EExecutionState *state) const;
    uint64_t getPeakCommitCharge(S2EExecutionState *state) const;

private:
    // TODO: use a generic interface
    WindowsMonitor *m_monitor;

    void updateMemoryStats(S2EExecutionState *state);

    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
    void onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &d);
    void onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &d);
    void onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &d);
    void onNtMapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_MAP_SECTION &d);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &d);
};

/* Maps a region to a set of flags */
typedef llvm::IntervalMap<uint64_t, MemoryMapRegionType> MemoryMapRegion;

/* Maintains a region map for each process id */
typedef llvm::DenseMap<uint64_t, MemoryMapRegion *> MemoryMapRegionProcess;

class MemoryMapRegionManager {
private:
    MemoryMapRegionProcess m_regions;
    MemoryMapRegion::Allocator m_alloc;

public:
    void addRegion(uint64_t pid, uint64_t addr, uint64_t end, MemoryMapRegionType type) {
        assert(end > addr);
        removeRegion(pid, addr, end); // FIXME: make it faster

        MemoryMapRegion *map = getMap(pid);
        map->insert(addr, end - 1, type);
    }

    void removeRegion(uint64_t target_pid, uint64_t addr, uint64_t end) {
        assert(end > addr);

        MemoryMapRegion &map = *getMap(target_pid);

        MemoryMapRegion::iterator ie = map.end();
        MemoryMapRegion::iterator it;

        while (((it = map.find(addr)) != ie) && (it.start() < end)) {
            uint64_t it_addr = it.start();
            uint64_t it_end = it.stop();
            MemoryMapRegionType type = (*it);
            it.erase();

            if (it_addr < addr) {
                map.insert(it_addr, addr - 1, type);
            }
            if (it_end > end - 1) {
                map.insert(end, it_end, type);
            }
        }
    }

    MemoryMapRegionType lookupRegion(uint64_t pid, uint64_t addr) const {
        MemoryMapRegionProcess::const_iterator it = m_regions.find(pid);
        if (it == m_regions.end()) {
            return MM_NONE;
        }

        return (*it).second->lookup(addr, MM_NONE);
    }

    void removePid(uint64_t pid) {
        MemoryMapRegionProcess::iterator it = m_regions.find(pid);
        if (it != m_regions.end()) {
            delete ((*it).second);
            m_regions.erase(it);
        }
    }

    void dump(llvm::raw_ostream &os) const {
        foreach2 (it, m_regions.begin(), m_regions.end()) {
            uint64_t pid = (*it).first;
            const MemoryMapRegion *p = (*it).second;

            foreach2 (iit, p->begin(), p->end()) {
                uint64_t it_addr = iit.start();
                uint64_t it_end = iit.stop();
                MemoryMapRegionType type = (*iit);
                os << "pid=" << hexval(pid);
                os << " [" << hexval(it_addr) << ", " << hexval(it_end) << "] ";
                os << (type & MM_READ ? 'R' : '-');
                os << (type & MM_WRITE ? 'W' : '-');
                os << (type & MM_EXEC ? 'X' : '-');
                os << "\n";
            }
        }
    }

    ~MemoryMapRegionManager() {
        foreach2 (it, m_regions.begin(), m_regions.end()) { delete (*it).second; }
    }

private:
    MemoryMapRegion *getMap(uint64_t pid) {
        MemoryMapRegionProcess::iterator it = m_regions.find(pid);
        MemoryMapRegion *map;
        if (it == m_regions.end()) {
            map = new MemoryMapRegion(m_alloc);
            m_regions[pid] = map;
        } else {
            map = (*it).second;
        }
        return map;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MemoryMap_H
