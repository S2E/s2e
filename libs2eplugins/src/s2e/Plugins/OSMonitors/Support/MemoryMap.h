///
/// Copyright (C) 2014-2015, Cyberhaven
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

#ifndef S2E_PLUGINS_MemoryMap_H
#define S2E_PLUGINS_MemoryMap_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2EExecutionState.h>

#include <functional>

namespace s2e {
namespace plugins {

typedef unsigned MemoryMapRegionType;
static const unsigned MM_NONE = 0;
static const unsigned MM_READ = 1;
static const unsigned MM_WRITE = 2;
static const unsigned MM_EXEC = 4;

typedef std::function<bool(uint64_t, uint64_t, MemoryMapRegionType)> MemoryMapCb;

///
/// \brief This plugin keeps track of allocated memory regions in tracked processes.
///
/// In order to use this plugin, configure ProcessExecutionDetector first with
/// the process names of which you want to know the memory map. You can then use
/// this plugin to query region types (read, write, exec) for given pid/address pairs.
///
class MemoryMap : public Plugin {
    S2E_PLUGIN
public:
    MemoryMap(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    ///
    /// \brief determines the region type of the given address
    /// \param state the execution state where the region will be searched
    /// \param pid the process id that contains the given address
    /// \param address the address to query
    /// \return the region type
    ///
    MemoryMapRegionType getType(S2EExecutionState *state, uint64_t pid, uint64_t address) const;

    ///
    /// \brief Retrieves information about the memory region of the given address
    /// \param state the execution state where the region will be searched
    /// \param pid the process id that contains the given address
    /// \param addr the address to query
    /// \param start the first byte of the region
    /// \param end the last byte of the region
    /// \param type the region type
    /// \return true if a region such that start <= addr <= end could be found.
    ///
    bool lookupRegion(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t &start, uint64_t &end,
                      MemoryMapRegionType &type) const;

    ///
    /// \brief iterates over all regions of the given state/pid while invoking the
    /// specified callback
    ///
    /// \param state the execution state
    /// \param pid the program id
    /// \param callback the function to invoke for each memory region
    ///
    void iterateRegions(S2EExecutionState *state, uint64_t pid, MemoryMapCb callback) const;

    ///
    /// \brief return the peak commit charge (Windows-specifiec)
    /// \param state the execution state
    /// \return the commit charge
    ///
    uint64_t getPeakCommitCharge(S2EExecutionState *state) const;

    ///
    /// \brief dump the memory map of all tracked processes
    /// \param state the execution state
    ///
    void dump(S2EExecutionState *state) const;

    ///
    /// \brief dump the memory map of the given tracked process
    /// \param state the execution state
    /// \param pid the pid of the process to dump
    ///
    void dump(S2EExecutionState *state, uint64_t pid) const;

private:
    OSMonitor *m_monitor;
    WindowsMonitor *m_windows;
    ProcessExecutionDetector *m_proc;

    void updateMemoryStats(S2EExecutionState *state);

    void onDecreeUpdateMemoryMap(S2EExecutionState *state, uint64_t pid, const s2e::plugins::S2E_DECREEMON_VMA &vma);
    void onLinuxMemoryMap(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t size, uint64_t prot);
    void onLinuxMemoryUnmap(S2EExecutionState *state, uint64_t pid, uint64_t addr, uint64_t size);

    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
    void onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &d);
    void onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &d);
    void onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &d);
    void onNtMapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_MAP_SECTION &d);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &d);

    void addRegion(S2EExecutionState *state, uint64_t pid, uint64_t start, uint64_t end, MemoryMapRegionType type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MemoryMap_H
