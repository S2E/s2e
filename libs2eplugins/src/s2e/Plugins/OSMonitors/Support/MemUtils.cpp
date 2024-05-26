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

#include "MemUtils.h"

namespace s2e {
namespace plugins {

using namespace klee;

S2E_DEFINE_PLUGIN(MemUtils, "Various memory-related utilities that require OS support", "", "ModuleMap", "Vmi",
                  "MemoryMap");

void MemUtils::initialize() {
    m_vmi = s2e()->getPlugin<Vmi>();
    m_map = s2e()->getPlugin<ModuleMap>();
    m_memmap = s2e()->getPlugin<MemoryMap>();
}

ref<Expr> MemUtils::read(S2EExecutionState *state, uint64_t addr, klee::Expr::Width width) {
    ref<Expr> expr = state->mem()->read(addr, width);
    if (expr) {
        return expr;
    }

    // Try to read data from executable image
    auto module = m_map->getModule(state, state->regs()->getPc());
    if (!module) {
        getDebugStream(state) << "no current module\n";
        return ref<Expr>(nullptr);
    }

    uintmax_t value = 0;
    for (unsigned i = 0; i < Expr::getMinBytesForWidth(width); i++) {
        uint8_t byte;
        if (!m_vmi->readModuleData(*module, addr + i, byte)) {
            getDebugStream(state) << "Failed to read memory at address " << hexval(addr) << "\n";
            return ref<Expr>(nullptr);
        }
        value |= ((uintmax_t) byte) << (i * CHAR_BIT);
    }

    return ConstantExpr::create(value, width);
}

klee::ref<klee::Expr> MemUtils::read(S2EExecutionState *state, uint64_t addr) {
    return read(state, addr, Expr::Int8);
}

bool MemUtils::read(S2EExecutionState *state, std::vector<ref<Expr>> &output, uint64_t address, unsigned length) {
    for (unsigned i = 0; i < length; ++i) {
        ref<Expr> e = read(state, address + i);
        if (!e) {
            getWarningsStream(state) << "Could not read byte at " << hexval(address + i) << "\n";
            return false;
        }
        output.push_back(e);
    }
    return true;
}

void MemUtils::findSequencesOfSymbolicData(const BitArrayPtr &concreteMask, uint64_t baseAddr, AddrSize *prevItem,
                                           std::vector<AddrSize> &sequences) {
    unsigned maskSize = concreteMask->getBitCount();

    if (!concreteMask || concreteMask->isAllOnes()) {
        return;
    }

    unsigned size = 0;
    unsigned offset;

    // Walk through all bits (plus one more to terminate sequence ending on page boundary)
    for (unsigned int i = 0; i <= maskSize; i++) {
        if (i != maskSize && !concreteMask->get(i)) {
            // first symbolic byte, remember its position
            if (!size) {
                offset = i;
            }

            size++;
        } else {
            // concrete byte again, nothing to do
            if (!size) {
                continue;
            }

            // symbolic sequence terminated
            if (offset == 0 && prevItem && prevItem->addr + prevItem->size == baseAddr) {
                // merge with previous sequence
                prevItem->size += size;
            } else {
                sequences.push_back(AddrSize(baseAddr + offset, size));
            }

            size = 0;
        }
    }
}

void MemUtils::findSequencesOfSymbolicData(S2EExecutionState *state, const std::set<uint64_t> &sortedPages,
                                           std::vector<AddrSize> &symbolicSequences) {
    foreach2 (it, sortedPages.begin(), sortedPages.end()) {
        auto os = state->mem()->getMemoryObject(*it);
        if (!os) { // page was not used/mapped
            continue;
        }

        auto concreteMask = os->getConcreteMask();
        if (!concreteMask) { // all bytes are concrete
            continue;
        }

        // Even if ObjectState was split, it must use same concreteMask object.
        assert(concreteMask->getBitCount() == TARGET_PAGE_SIZE);

        // Last item from previous page (assume pages (and thus items) are sorted)
        AddrSize *prevItem = symbolicSequences.size() ? &symbolicSequences.back() : nullptr;

        findSequencesOfSymbolicData(concreteMask, *it, prevItem, symbolicSequences);
    }
}

void MemUtils::findSequencesOfSymbolicData(S2EExecutionState *state, uint64_t pid, bool mustBeExecutable,
                                           std::vector<AddrSize> &symbolicSequences) {
    std::set<uint64_t> pages;

    auto lambda = [&](uint64_t start, uint64_t end, MemoryMapRegionType type) -> bool {
        if (!(type & MM_READ)) {
            return true;
        }

        if (mustBeExecutable && (type & MM_EXEC)) {
            for (uint64_t s = start; s < end; s += TARGET_PAGE_SIZE) {
                pages.insert(s & TARGET_PAGE_MASK);
            }
        }

        return true;
    };

    m_memmap->iterateRegions(state, pid, lambda);

    findSequencesOfSymbolicData(state, pages, symbolicSequences);
}

void MemUtils::findMemoryPages(S2EExecutionState *state, uint64_t pid, bool mustBeWritable, bool mustBeExecutable,
                               RegionMap<MemoryMapRegionType> &pages) {
    auto lambda = [&](uint64_t start, uint64_t end, MemoryMapRegionType type) {
        bool doAdd = false;

        if (!mustBeWritable && (type & MM_READ)) {
            doAdd = true;
        }

        if (mustBeWritable && (type & MM_WRITE)) {
            doAdd = true;
        }

        if (mustBeExecutable && (type & MM_EXEC)) {
            doAdd = true;
        }

        if (doAdd) {
            pages.add(start, end, type);
        }

        return true;
    };

    m_memmap->iterateRegions(state, pid, lambda);
}
} // namespace plugins
} // namespace s2e
