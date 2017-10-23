///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MemoryMap.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryMap, "MemoryMap S2E plugin", "", "WindowsMonitor");

// Maps a pid to the pointer size
typedef llvm::DenseSet<uint64_t> TrackedPidsMap;

static MemoryMapRegionType WindowsProtectionToInternal(uint64_t protection) {
    uint64_t type = MM_NONE;
    protection = protection & 0xff;
    if (protection & 0xf0) {
        type = (MemoryMapRegionType)(type | MM_EXEC);
        protection >>= 4;
    }

    switch (protection) {
        case PAGE_NOACCESS:
            type |= MM_NONE;
            break;
        case PAGE_READONLY:
            type |= MM_READ;
            break;
        case PAGE_READWRITE:
            type |= MM_READ | MM_WRITE;
            break;
        case PAGE_WRITECOPY:
            type |= MM_READ | MM_WRITE;
            break;
        default:
            assert(false && "Unknown protection flag");
    }

    return (MemoryMapRegionType) type;
}

class MemoryMapState : public PluginState {
private:
    Plugin *m_plugin;

public:
    TrackedPidsMap m_trackedPids;
    /* Manage per-process memory stats */
    typedef llvm::DenseMap<uint64_t, WindowsMonitor::MemoryInformation> MemoryInfoMap;
    MemoryInfoMap m_memoryInfo;

    uint64_t m_peakCommitCharge;

    MemoryMapRegionManager m_manager;

    void addRegion(uint64_t pid, uint64_t addr, uint64_t end, MemoryMapRegionType type) {
        m_manager.addRegion(pid, addr, end, type);
        m_plugin->getDebugStream() << "MemoryMap: adding region: [" << hexval(addr) << ", " << hexval(end) << "]\n";
    }

    void removeRegion(uint64_t target_pid, uint64_t addr, uint64_t end) {
        m_plugin->getDebugStream() << "MemoryMap: removing region: [" << hexval(addr) << ", " << hexval(end) << "]\n";
        m_manager.removeRegion(target_pid, addr, end);
    }

    MemoryMapRegionType lookupRegion(uint64_t pid, uint64_t addr) const {
        return m_manager.lookupRegion(pid, addr);
    }

    void removePid(uint64_t pid) {
        m_manager.removePid(pid);

        MemoryInfoMap::iterator mit = m_memoryInfo.find(pid);
        if (mit != m_memoryInfo.end()) {
            m_memoryInfo.erase(mit);
        }
    }

    virtual MemoryMapState *clone() const {
        assert(0); // XXX
        /// XXX: must copy the interval map
        return NULL;
        // MemoryMapState *ret = new MemoryMapState(m_regionsAlloc);
        // return ret;
    }

    MemoryMapState(Plugin *p) {
        m_peakCommitCharge = 0;
        m_plugin = p;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new MemoryMapState(p);
    }

    void updateMemoryStats(const WindowsMonitor::MemoryInformation &stats, uint64_t pid) {
        m_memoryInfo[pid] = stats;

        /** Report aggregated memory usage for all tracked processes */
        uint64_t totalCommitChargePeak = 0;
        foreach2 (it, m_memoryInfo.begin(), m_memoryInfo.end()) {
            totalCommitChargePeak += (*it).second.PeakCommitCharge;
        }

        if (totalCommitChargePeak > m_peakCommitCharge) {
            m_peakCommitCharge = totalCommitChargePeak;
        }
    }

    uint64_t getPeakCommitCharge() const {
        return m_peakCommitCharge * 4096;
    }

    void dump(llvm::raw_ostream &os) const {
        m_manager.dump(os);
    }
};

void MemoryMap::initialize() {
    m_monitor = s2e()->getPlugin<WindowsMonitor>();

    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &MemoryMap::onProcessUnload));

    m_monitor->onNtAllocateVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtAllocateVirtualMemory));

    m_monitor->onNtFreeVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtFreeVirtualMemory));

    m_monitor->onNtProtectVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtProtectVirtualMemory));

    m_monitor->onNtMapViewOfSection.connect(sigc::mem_fun(*this, &MemoryMap::onNtMapViewOfSection));

    m_monitor->onNtUnmapViewOfSection.connect(sigc::mem_fun(*this, &MemoryMap::onNtUnmapViewOfSection));
}

void MemoryMap::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode) {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    plgState->removePid(pid);
}

void MemoryMap::onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &d) {
    using namespace vmi::windows;
    if (!NT_SUCCESS(d.Status)) {
        return;
    }

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    assert(pid);

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    uint64_t target_pid = m_monitor->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size)
                     << " protect=" << hexval(d.Protection) << "\n";

    uint64_t address = d.BaseAddress;
    uint64_t size = d.Size;

    uint64_t end = address + size;
    address &= ~0xfff;
    end = (end + 0xfff) & ~0xfff;

    MemoryMapRegionType type = WindowsProtectionToInternal(d.Protection);

    addRegion(state, real_pid, address, end, type);
}

void MemoryMap::addRegion(S2EExecutionState *state, uint64_t pid, uint64_t address, uint64_t end,
                          MemoryMapRegionType type) {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        return;
    }

    plgState->addRegion(pid, address, end, type);
}

void MemoryMap::onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &d) {
    if (d.Status != 0) {
        return;
    }

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    uint64_t pid = m_monitor->getCurrentProcessId(state);
    assert(pid);

    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    uint64_t target_pid = m_monitor->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size) << "\n";

    if (d.FreeType & 0x8000 || d.FreeType & 0x4000) { // MEM_RELEASE || MEM_DECOMMIT
        uint64_t address = d.BaseAddress;
        uint64_t size = d.Size;
        uint64_t end = address + size;
        address &= ~0xfff;
        end = (end + 0xfff) & ~0xfff;

        plgState->removeRegion(real_pid, address, end);
    }
}

void MemoryMap::onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &d) {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    uint64_t pid = m_monitor->getCurrentProcessId(state);
    assert(pid);

    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    uint64_t target_pid = m_monitor->getPidFromHandle(state, pid, d.ProcessHandle);

    uint64_t address = d.BaseAddress;
    uint64_t end = d.BaseAddress + d.Size;
    address = address & ~0xfff;
    end = (end + 0xfff) & ~0xfff;

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size)
                     << " protection=" << hexval(d.NewProtection) << "\n";

    MemoryMapRegionType type = WindowsProtectionToInternal(d.NewProtection);

    plgState->addRegion(target_pid ? target_pid : pid, address, end, type);
}

void MemoryMap::onNtMapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_MAP_SECTION &d) {
    // Unused?
}

void MemoryMap::onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &d) {
    // Unused?
}

void MemoryMap::updateMemoryStats(S2EExecutionState *state) {
    WindowsMonitor::MemoryInformation info;
    if (m_monitor->getMemoryStatisticsForCurrentProcess(state, info)) {
        DECLARE_PLUGINSTATE(MemoryMapState, state);
        uint64_t pid = m_monitor->getCurrentProcessId(state);
        plgState->updateMemoryStats(info, pid);
    }
}

MemoryMapRegionType MemoryMap::getType(S2EExecutionState *state, uint64_t pid, uint64_t address) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    return plgState->lookupRegion(pid, address);
}

void MemoryMap::trackPid(S2EExecutionState *state, uint64_t pid, bool track) {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    if (track) {
        plgState->m_trackedPids.insert(pid);
    } else {
        plgState->m_trackedPids.erase(pid);
    }
}

void MemoryMap::dump(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);

    llvm::raw_ostream &os = getDebugStream(state);
    os << "Dumping memory map\n";
    plgState->dump(os);
}

uint64_t MemoryMap::getPeakCommitCharge(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    return plgState->getPeakCommitCharge();
}

} // namespace plugins
} // namespace s2e
