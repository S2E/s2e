///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2018, Cyberhaven
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

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/IntervalMap.h>

#include <unordered_map>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include "IntervalMapWrapper.h"
#include "MemoryMap.h"
#include "RegionMap.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryMap, "MemoryMap S2E plugin", "", "OSMonitor", "ProcessExecutionDetector");

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
            pabort("Unknown protection flag");
    }

    return (MemoryMapRegionType) type;
}

namespace {

class MemoryMapRegionManager : public ProcessRegionMapManager<MemoryMapRegionType> {
public:
    void dump(llvm::raw_ostream &os, uint64_t pid) const {
        RegionMapIteratorCb<MemoryMapRegionType> lambda = [&](uint64_t start, uint64_t end,
                                                              MemoryMapRegionType type) -> bool {
            os << "pid=" << hexval(pid);
            os << " [" << hexval(start) << ", " << hexval(end) << "] ";
            os << (type & MM_READ ? 'R' : '-');
            os << (type & MM_WRITE ? 'W' : '-');
            os << (type & MM_EXEC ? 'X' : '-');
            os << "\n";

            return true;
        };

        iterate(pid, lambda);
    }

    void dump(llvm::raw_ostream &os) const {
        for (auto it = m_regions.begin(); it != m_regions.end(); ++it) {
            uint64_t pid = (*it).first;
            dump(os, pid);
        }
    }
};

class MemoryMapState : public PluginState {
private:
    Plugin *m_plugin;

public:
    /* Manage per-process memory stats */
    typedef llvm::DenseMap<uint64_t, WindowsMonitor::MemoryInformation> MemoryInfoMap;
    MemoryInfoMap m_memoryInfo;

    uint64_t m_peakCommitCharge;

    MemoryMapRegionManager m_manager;

    void addRegion(uint64_t pid, uint64_t start, uint64_t end, MemoryMapRegionType type) {
        m_manager.add(pid, start, end, type);
        m_plugin->getDebugStream() << "adding region:"
                                   << " pid=" << hexval(pid) << " [" << hexval(start) << ", " << hexval(end) << "]\n";
    }

    void removeRegion(uint64_t pid, uint64_t start, uint64_t end) {
        m_plugin->getDebugStream() << "removing region: "
                                   << " pid=" << hexval(pid) << "[" << hexval(start) << ", " << hexval(end) << "]\n";
        m_manager.remove(pid, start, end);
    }

    MemoryMapRegionType lookupRegion(uint64_t pid, uint64_t addr) const {
        return m_manager.lookup(pid, addr);
    }

    bool lookupRegion(uint64_t pid, uint64_t addr, uint64_t &start, uint64_t &end, MemoryMapRegionType &type) const {
        return m_manager.lookup(pid, addr, start, end, type);
    }

    void iterateRegions(uint64_t pid, MemoryMapCb &callback) const {
        return m_manager.iterate(pid, callback);
    }

    void removePid(uint64_t pid) {
        m_manager.remove(pid);

        MemoryInfoMap::iterator mit = m_memoryInfo.find(pid);
        if (mit != m_memoryInfo.end()) {
            m_memoryInfo.erase(mit);
        }
    }

    virtual MemoryMapState *clone() const {
        return new MemoryMapState(*this);
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
        for (auto &it : m_memoryInfo) {
            totalCommitChargePeak += it.second.PeakCommitCharge;
        }

        if (totalCommitChargePeak > m_peakCommitCharge) {
            m_peakCommitCharge = totalCommitChargePeak;
        }
    }

    uint64_t getPeakCommitCharge() const {
        return m_peakCommitCharge * TARGET_PAGE_SIZE;
    }

    void dump(llvm::raw_ostream &os) const {
        m_manager.dump(os);
    }

    void dump(llvm::raw_ostream &os, uint64_t pid) const {
        m_manager.dump(os, pid);
    }
};
} // namespace

void MemoryMap::initialize() {
    m_proc = s2e()->getPlugin<ProcessExecutionDetector>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    // Register generic events
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &MemoryMap::onProcessUnload));

    // Register Windows events
    m_windows = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (m_windows) {
        m_windows->onNtAllocateVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtAllocateVirtualMemory));
        m_windows->onNtFreeVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtFreeVirtualMemory));
        m_windows->onNtProtectVirtualMemory.connect(sigc::mem_fun(*this, &MemoryMap::onNtProtectVirtualMemory));
        m_windows->onNtMapViewOfSection.connect(sigc::mem_fun(*this, &MemoryMap::onNtMapViewOfSection));
        m_windows->onNtUnmapViewOfSection.connect(sigc::mem_fun(*this, &MemoryMap::onNtUnmapViewOfSection));
        return;
    }

    // Register Decree events
    DecreeMonitor *decree = dynamic_cast<DecreeMonitor *>(m_monitor);
    if (decree) {
        decree->onUpdateMemoryMap.connect(sigc::mem_fun(*this, &MemoryMap::onDecreeUpdateMemoryMap));
        return;
    }

    // Register Linux events
    LinuxMonitor *linmon = dynamic_cast<LinuxMonitor *>(m_monitor);
    if (linmon) {
        linmon->onMemoryMap.connect(sigc::mem_fun(*this, &MemoryMap::onLinuxMemoryMap));
        linmon->onMemoryUnmap.connect(sigc::mem_fun(*this, &MemoryMap::onLinuxMemoryUnmap));

        // Memory protect and mapping share the same handler
        linmon->onMemoryProtect.connect(sigc::mem_fun(*this, &MemoryMap::onLinuxMemoryMap));
        return;
    }
}

void MemoryMap::addRegion(S2EExecutionState *state, uint64_t pid, uint64_t address, uint64_t end,
                          MemoryMapRegionType type) {
    // Don't check if the pid is tracked, this is a private method and the caller
    // is reponsible for the check.
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    pid = m_monitor->translatePid(pid, address);
    plgState->addRegion(pid, address, end, type);
}

///
/// \brief Rounds down address to the nearest page boundary, rounds up
/// address + size to the nearest page boundary.
///
/// E.g., address==1 and size==2 => start==0 and end == 0x1000;
///
static void ComputeStartEndAddress(uint64_t address, uint64_t size, uint64_t &start, uint64_t &end) {
    start = address & TARGET_PAGE_MASK;
    end = (address + size + (TARGET_PAGE_SIZE - 1)) & TARGET_PAGE_MASK;
}

void MemoryMap::onLinuxMemoryMap(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t size, uint64_t prot) {
    if (!m_proc->isTracked(state, pid)) {
        return;
    }

    MemoryMapRegionType type = MM_NONE;

    if (prot & PROT_READ) {
        type |= MM_READ;
    }

    if (prot & PROT_WRITE) {
        type |= MM_WRITE;
    }

    if (prot & PROT_EXEC) {
        type |= MM_EXEC;
    }

    uint64_t start, end;
    ComputeStartEndAddress(addr, size, start, end);

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    plgState->addRegion(pid, start, end, type);
}

void MemoryMap::onLinuxMemoryUnmap(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t size) {
    if (!m_proc->isTracked(state, pid)) {
        return;
    }
    uint64_t start, end;
    ComputeStartEndAddress(addr, size, start, end);

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    plgState->removeRegion(pid, start, end);
}

void MemoryMap::onDecreeUpdateMemoryMap(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_VMA &vma) {
    if (!m_proc->isTracked(state, pid)) {
        return;
    }

    MemoryMapRegionType type = MM_NONE;

    if (vma.flags & S2E_DECREEMON_VM_READ) {
        type |= MM_READ;
    }

    if (vma.flags & S2E_DECREEMON_VM_WRITE) {
        type |= MM_WRITE;
    }

    if (vma.flags & S2E_DECREEMON_VM_EXEC) {
        type |= MM_EXEC;
    }

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    plgState->addRegion(pid, vma.start, vma.end, type);
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

    uint64_t pid = m_windows->getCurrentProcessId(state);
    assert(pid);

    uint64_t target_pid = m_windows->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    if (!m_proc->isTracked(state, real_pid)) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size)
                     << " protect=" << hexval(d.Protection) << "\n";

    uint64_t start;
    uint64_t end;
    ComputeStartEndAddress(d.BaseAddress, d.Size, start, end);

    MemoryMapRegionType type = WindowsProtectionToInternal(d.Protection);
    addRegion(state, real_pid, start, end, type);
}

void MemoryMap::onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &d) {
    if (d.Status != 0) {
        return;
    }

    uint64_t pid = m_windows->getCurrentProcessId(state);
    assert(pid);

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    uint64_t target_pid = m_windows->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    if (!m_proc->isTracked(state, real_pid)) {
        return;
    }

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size) << "\n";

    if (d.FreeType & 0x8000 || d.FreeType & 0x4000) { // MEM_RELEASE || MEM_DECOMMIT
        uint64_t start;
        uint64_t end;
        ComputeStartEndAddress(d.BaseAddress, d.Size, start, end);

        DECLARE_PLUGINSTATE(MemoryMapState, state);
        plgState->removeRegion(real_pid, start, end);
    }
}

void MemoryMap::onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &d) {
    uint64_t pid = m_windows->getCurrentProcessId(state);
    assert(pid);

    uint64_t target_pid = m_windows->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    if (!m_proc->isTracked(state, real_pid)) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size)
                     << " protection=" << hexval(d.NewProtection) << "\n";

    uint64_t start;
    uint64_t end;
    ComputeStartEndAddress(d.BaseAddress, d.Size, start, end);

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    MemoryMapRegionType type = WindowsProtectionToInternal(d.NewProtection);
    plgState->addRegion(real_pid, start, end, type);
}

void MemoryMap::onNtMapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_MAP_SECTION &d) {
    uint64_t pid = m_windows->getCurrentProcessId(state);
    assert(pid);

    uint64_t target_pid = m_windows->getPidFromHandle(state, pid, d.ProcessHandle);
    uint64_t real_pid = target_pid ? target_pid : pid;

    if (!m_proc->isTracked(state, real_pid)) {
        return;
    }

    // XXX: this will not update stats for a remote process!
    updateMemoryStats(state);

    getDebugStream() << __FUNCTION__ << " pid=" << hexval(pid) << " target pid=" << hexval(target_pid)
                     << " base=" << hexval(d.BaseAddress) << " size=" << hexval(d.Size)
                     << " protection=" << hexval(d.Win32Protect) << "\n";

    uint64_t start;
    uint64_t end;
    ComputeStartEndAddress(d.BaseAddress, d.Size, start, end);

    DECLARE_PLUGINSTATE(MemoryMapState, state);
    MemoryMapRegionType type = WindowsProtectionToInternal(d.Win32Protect);
    plgState->addRegion(real_pid, start, end, type);
}

void MemoryMap::onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &d) {
    // XXX: not implemented. This would require to convert somehow the given address
    // to the section start and size.
}

void MemoryMap::updateMemoryStats(S2EExecutionState *state) {
    if (!m_windows) {
        getWarningsStream(state) << "updateMemoryStats requires WindowsMonitor\n";
        return;
    }

    WindowsMonitor::MemoryInformation info;
    if (m_windows->getMemoryStatisticsForCurrentProcess(state, info)) {
        DECLARE_PLUGINSTATE(MemoryMapState, state);
        uint64_t pid = m_windows->getCurrentProcessId(state);
        plgState->updateMemoryStats(info, pid);
    }
}

MemoryMapRegionType MemoryMap::getType(S2EExecutionState *state, uint64_t pid, uint64_t address) const {
    DECLARE_PLUGINSTATE_CONST(MemoryMapState, state);
    return plgState->lookupRegion(pid, address);
}

bool MemoryMap::lookupRegion(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t &start, uint64_t &end,
                             MemoryMapRegionType &type) const {
    DECLARE_PLUGINSTATE_CONST(MemoryMapState, state);
    return plgState->lookupRegion(pid, addr, start, end, type);
}

void MemoryMap::iterateRegions(S2EExecutionState *state, uint64_t pid, MemoryMapCb callback) const {
    DECLARE_PLUGINSTATE_CONST(MemoryMapState, state);
    return plgState->iterateRegions(pid, callback);
}

void MemoryMap::dump(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);

    llvm::raw_ostream &os = getDebugStream(state);
    os << "Dumping memory map\n";
    plgState->dump(os);
}

void MemoryMap::dump(S2EExecutionState *state, uint64_t pid) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);

    llvm::raw_ostream &os = getDebugStream(state);
    os << "Dumping memory map for pid " << pid << "\n";
    plgState->dump(os, pid);
}

uint64_t MemoryMap::getPeakCommitCharge(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE(MemoryMapState, state);
    return plgState->getPeakCommitCharge();
}

} // namespace plugins
} // namespace s2e
