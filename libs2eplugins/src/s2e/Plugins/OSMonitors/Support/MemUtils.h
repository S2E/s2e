///
/// Copyright (C) 2018, Cyberhaven
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

#ifndef S2E_PLUGINS_OSMONITOR_MEMUTILS_H
#define S2E_PLUGINS_OSMONITOR_MEMUTILS_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/RegionMap.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Expr.h>
#include <unordered_set>
#include <vector>

namespace s2e {
namespace plugins {

///
/// \brief This plugin exports various memory-related APIs that provide more robust
/// memory accessors.
///
/// A common issue when writing a plugin is to be able to read data from executable files
/// mapped to guest virtual memory. This is may be impossible to do if the guest did not
/// map the memory yet (e.g., demand paging). This plugin provides a fallback mechanism in
/// case of read failure by reverting to executable files stored on the host file system.
///
/// This works as follows:
/// 1. Try to read memory directly, if success, return immediately
/// 2. Determine the module loaded at the given location. Return error in case of failure.
/// 3. Load the binary from disk and attempt a read from there.
///
class MemUtils : public Plugin {
    S2E_PLUGIN

private:
    ModuleMap *m_map;
    MemoryMap *m_memmap;
    Vmi *m_vmi;

public:
    struct AddrSize {
        uint64_t addr;
        size_t size;

        AddrSize(uint64_t addr, size_t size) : addr(addr), size(size) {
        }

        bool operator<(const AddrSize &x) const {
            return (size < x.size);
        }
    };

    MemUtils(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    klee::ref<klee::Expr> read(S2EExecutionState *state, uint64_t addr);
    klee::ref<klee::Expr> read(S2EExecutionState *state, uint64_t addr, klee::Expr::Width width);
    bool read(S2EExecutionState *state, std::vector<klee::ref<klee::Expr>> &output, uint64_t address, unsigned length);

    /// \brief findSequencesOfSymbolicData
    /// Find contiguous regions of symbolic data described by an
    /// AddrSize structure. Walks through all bits in concreteMask to create
    /// a list of contiguous symbolic bytes.
    ///
    /// E.g., for bitmask 1001110000 it will find 2 sequences with sizes 2 and 4
    /// (0 bit means symbolic).
    ///
    /// \param sequences The resulting list of regions
    /// \param concreteMask Mask that specifies whether each byte of a region is symbolic or not
    /// \param baseAddr The virtual base address of the first bit in concreteMask
    /// \param prevItem Used to automatically merge sequence spanning 2 memory pages.
    /// If the function is called with bitmask 111000 and then 0111, it will update previously
    /// found sequence to have size 4.
    void findSequencesOfSymbolicData(const klee::BitArrayPtr &concreteMask, uint64_t baseAddr, AddrSize *prevItem,
                                     std::vector<AddrSize> &sequences);

    /// \brief Find contiguous chunks of symbolic data in selected memory pages
    ///
    /// \param state current state
    /// \param pages memory pages where to search for symbolic data
    /// \param symbolicSequences discovered sequences of symbolic data
    void findSequencesOfSymbolicData(S2EExecutionState *state, const std::set<uint64_t> &sortedPages,
                                     std::vector<AddrSize> &symbolicSequences);

    /// \brief Find contiguous chunks of symbolic data with given memory layout
    ///
    /// \param state current state
    /// \param map memory map
    /// \param mustBeExecutable true if symbolic data must be executable
    /// \param symbolicSequences discovered sequences of symbolic data
    void findSequencesOfSymbolicData(S2EExecutionState *state, uint64_t pid, bool mustBeExecutable,
                                     std::vector<AddrSize> &symbolicSequences);

    void findMemoryPages(S2EExecutionState *state, uint64_t pid, bool mustBeWritable, bool mustBeExecutable,
                         RegionMap<MemoryMapRegionType> &pages);
};
} // namespace plugins
} // namespace s2e

#endif
