///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <klee/AddressSpace.h>
#include <llvm/Support/CommandLine.h>
#include <s2e/cpu.h>
#include <s2e/s2e_libcpu.h>

#include <s2e/S2EExecutionStateTlb.h>
#include <s2e/Utils.h>
#include <s2e/s2e_config.h>

// #define S2E_DEBUG_TLBCACHE

#ifdef S2E_DEBUG_TLBCACHE
#include <s2e/S2E.h>
#else
// Undefine cat from "compiler.h"
#undef cat
#endif

extern llvm::cl::opt<bool> PrintModeSwitch;

namespace {
llvm::cl::opt<bool> TlbAudit("tlb-audit", llvm::cl::desc("Check the TLB cache map against the TLB after every update"),
                             llvm::cl::init(false));
}

namespace s2e {

using namespace klee;

namespace {
/// Number of entries of the main TLB of one MMU index.
inline unsigned tlbSize(CPUState *cpu, unsigned mmu_idx) {
    return (cpu->neg.tlb.f[mmu_idx].mask >> CPU_TLB_ENTRY_BITS) + 1;
}

/// The comparators, addend and se_addend of entry (mmu_idx, index).
inline CPUTLBEntry *fastEntry(CPUState *cpu, unsigned mmu_idx, unsigned index) {
    return &cpu->neg.tlb.f[mmu_idx].table[index];
}

/// The KLEE object that backs the page of entry (mmu_idx, index). The
/// pointer is in the full entry, which generated code does not read.
inline void *&entryObject(CPUState *cpu, unsigned mmu_idx, unsigned index) {
    return cpu->neg.tlb.d[mmu_idx].fulltlb[index].extra.object_state;
}
} // namespace

bool S2EExecutionStateTlb::addressSpaceChangeUpdateTlb(const klee::ObjectStateConstPtr &oldState,
                                                       const klee::ObjectStatePtr &newState) {
    if (!(oldState && oldState->isMemoryPage())) {
        return false;
    }

    // This can happen when KLEE unbinds the object after it was
    // split into multiple ones.
    if (!newState) {
        return false;
    }

    if (oldState->getStoreOffset()) {
        // This happens when a split object is COWed.
        // Since all split objects share the same concrete buffer,
        // we only need to process the first object of the page.
        // This assumes that KLEE will call getWritable on every
        // sub-object of the memory page.
        return false;
    }

    const auto &mo = oldState->getKey();
    assert(newState->isMemoryPage());

    if ((mo.address & ~SE_RAM_OBJECT_MASK)) {
        return false;
    }

    m_asCache->invalidate(mo.address & SE_RAM_OBJECT_MASK);
    updateTlb(oldState, newState);
#ifdef SE_ENABLE_PHYSRAM_TLB
    updateRamTlb(oldState, newState);
#endif
    return true;
}

#if defined(SE_ENABLE_PHYSRAM_TLB)
void S2EExecutionStateTlb::updateRamTlb(const klee::ObjectStateConstPtr &oldState,
                                        const klee::ObjectStatePtr &newState) {
    // An inactive state has no RAM TLB; it gets an empty one when activated.
    if (!*m_active) {
        return;
    }

    CPUState *cpu = m_registers->getCpuCaches();
    uintptr_t tlb_index = (oldState->getAddress() >> 12) & (CPU_TLB_SIZE - 1);
    CPUTLBRAMEntry *re = &cpu->neg.se_ram_tlb[tlb_index];

    assert(oldState->isSharedConcrete() == newState->isSharedConcrete());

    auto address = oldState->getAddress();

    if (!oldState->isSharedConcrete() && re->object_state == oldState) {
        assert((re->host_page & ~TLB_NOT_OURS) == address);
        if (newState->isAllConcrete()) {
            // XXX: use proper ref counting
            re->object_state = newState.get();
            re->host_page = address;
            re->addend = (uintptr_t) newState->getConcreteBufferPtr()->get() - address;
        }
        if (m_asCache->isOwnedByUs(newState)) {
            re->host_page &= ~TLB_NOT_OURS;
        }
    }
}
#endif

void S2EExecutionStateTlb::updateTlb(const klee::ObjectStateConstPtr &oldState, const klee::ObjectStatePtr &newState) {
    if (g_s2e_single_path_mode) {
        llvm::errs() << "Multi-path mode disabled.\n";
        exit(-1);
    }

    // An inactive state has no TLB, so there is nothing to repoint. Its map
    // must be empty: doStateSwitch() clears it on deactivation and a forked
    // state starts with an empty one.
    if (!*m_active) {
        if (!m_tlbMap.empty()) {
            pabort("Inactive state has a non-empty TLB cache map");
        }
        return;
    }

    CPUState *cpu = m_registers->getCpuCaches();

#ifdef S2E_DEBUG_TLBCACHE
    g_s2e->getDebugStream(g_s2e_state.get())
        << "updateTlb: Replacing " << hexval(oldState) << " by " << hexval(newState) << "\n";
    g_s2e->getDebugStream(g_s2e_state.get()) << "updateTlb: tlb map size=" << m_tlbMap.size() << '\n';
#endif

    assert(oldState->isSharedConcrete() == newState->isSharedConcrete());

    auto it = m_tlbMap.find(oldState);
    if (it != m_tlbMap.end()) {
        ObjectStateTlbReferences vec = (*it).second;
        unsigned size = vec.size();
        assert(size > 0);
        for (unsigned i = 0; i < size; ++i) {
            const TlbCoordinates &coords = vec[i];
#ifdef S2E_DEBUG_TLBCACHE
            g_s2e->getDebugStream() << "    mmu_idx=" << coords.first << " index=" << coords.second << "\n";
#endif
            CPUTLBEntry *entry = fastEntry(cpu, coords.first, coords.second);
            assert(entryObject(cpu, coords.first, coords.second) == (void *) oldState.get());
            assert(newState);

            // XXX: use proper refcounting
            entryObject(cpu, coords.first, coords.second) = newState.get();

            if (!newState->isSharedConcrete()) {
                // The addend does not change.
                entry->se_addend = entry->se_addend - (uintptr_t) oldState->getConcreteBuffer(true) +
                                   (uintptr_t) newState->getConcreteBuffer(true);

                if (m_asCache->isOwnedByUs(newState)) {
                    entry->addr_write &= ~TLB_NOT_OURS;
                }
            }

            updateTlbEntryConcreteStatus(coords.first, coords.second, newState);
        }

        m_tlbMap[newState] = vec;
        if (newState != oldState) {
            m_tlbMap.erase(oldState);
        }
    }

    if (TlbAudit && !audit()) {
        pabort("TLB cache audit failed");
    }
}

/***/

void S2EExecutionStateTlb::flushTlbCache() {
#ifdef S2E_DEBUG_TLBCACHE
    g_s2e->getDebugStream(g_s2e_state.get()) << "Flushing TLB cache\n";
#endif
    m_tlbMap.clear();
}

void S2EExecutionStateTlb::flushTlbCacheMmuIdx(int mmu_idx) {
    for (auto it = m_tlbMap.begin(); it != m_tlbMap.end();) {
        auto &vec = it->second;
        llvm::erase_if(vec, [&](const TlbCoordinates &coords) { return coords.first == (unsigned) mmu_idx; });
        if (vec.empty()) {
            it = m_tlbMap.erase(it);
        } else {
            ++it;
        }
    }
}

void S2EExecutionStateTlb::flushTlbCachePage(const klee::ObjectStatePtr &objectState, int mmu_idx, int index) {
    if (!objectState) {
        return;
    }

#ifdef S2E_DEBUG_TLBCACHE
    g_s2e->getDebugStream(g_s2e_state.get())
        << "flushTlbCachePage: clearing cache entry for " << objectState << " (" << mmu_idx << "," << index << ")\n";
#endif

    CPUState *cpu = m_registers->getCpuCaches();
    entryObject(cpu, mmu_idx, index) = nullptr;
    fastEntry(cpu, mmu_idx, index)->se_addend = 0;

    if (g_s2e_single_path_mode) {
        return;
    }

    bool found = false;
    TlbMap::iterator tlbIt = m_tlbMap.find(objectState);
    assert(tlbIt != m_tlbMap.end());

    ObjectStateTlbReferences &vec = (*tlbIt).second;
    foreach2 (vit, vec.begin(), vec.end()) {
        if ((*vit) == std::make_pair((unsigned) mmu_idx, (unsigned) index)) {
            vec.erase(vit);
            found = true;
            break;
        }
    }

    if (!found) {
        pabort("Invalid cache!");
    }

    if (vec.empty()) {
#ifdef S2E_DEBUG_TLBCACHE
        g_s2e->getDebugStream(g_s2e_state.get())
            << "flushTlbCachePage: Erasing cache entry for " << objectState << "\n";
#endif
        m_tlbMap.erase(tlbIt);
    }
}

/**
 * If a page contains at least one byte of symbolic data, it will go through
 * the slow path. Otherwise, softmmu will directly access the concrete array.
 */
void S2EExecutionStateTlb::updateTlbEntryConcreteStatus(unsigned mmu_idx, unsigned index,
                                                        const klee::ObjectStateConstPtr &state) {
    CPUState *cpu = m_registers->getCpuCaches();
    CPUTLBEntry *te = &cpu->neg.tlb.f[mmu_idx].table[index];

    if (!state->isAllConcrete()) {
        te->addr_read |= TLB_SYMB;
        te->addr_write |= TLB_SYMB;
        te->addr_code |= TLB_SYMB;
    } else {
        te->addr_read &= ~TLB_SYMB;
        te->addr_write &= ~TLB_SYMB;
        te->addr_code &= ~TLB_SYMB;
    }

#ifdef SE_ENABLE_PHYSRAM_TLB
    uintptr_t ram_tlb_index = (state->getAddress() >> 12) & (CPU_TLB_SIZE - 1);
    CPUTLBRAMEntry *re = &cpu->neg.se_ram_tlb[ram_tlb_index];
    re->host_page = 0;
    re->addend = 0;
    re->object_state = 0;
#endif
}

#if defined(SE_ENABLE_PHYSRAM_TLB)
void S2EExecutionStateTlb::clearRamTlb() {
    static CPUTLBRAMEntry empty = {0, 0, nullptr};
    CPUState *cpu = m_registers->getCpuCaches();
    for (unsigned i = 0; i < CPU_TLB_SIZE; i++) {
        cpu->neg.se_ram_tlb[i] = empty;
    }
}
#endif

void S2EExecutionStateTlb::clearTlbOwnership() {
    CPUState *cpu = m_registers->getCpuCaches();

    for (unsigned mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        for (unsigned i = 0; i < tlbSize(cpu, mmu_idx); i++) {
            fastEntry(cpu, mmu_idx, i)->addr_write |= TLB_NOT_OURS;
        }
    }
}

void S2EExecutionStateTlb::updateTlbEntry(int mmu_idx, uint64_t virtAddr, uint64_t hostAddr) {
    assert((hostAddr & ~TARGET_PAGE_MASK) == 0);
    assert((virtAddr & ~TARGET_PAGE_MASK) == 0);

    CPUState *cpu = m_registers->getCpuCaches();
    unsigned int index = (virtAddr >> TARGET_PAGE_BITS) & (tlbSize(cpu, mmu_idx) - 1);

    CPUTLBEntry *entry = fastEntry(cpu, mmu_idx, index);
    ObjectState *oldObjectState = static_cast<ObjectState *>(entryObject(cpu, mmu_idx, index));

    /* Retrieve the object state using the host address */
    auto newObjectState = m_asCache->get(hostAddr);
    assert(newObjectState);

/* Store the new mapping in the cache */
#ifdef S2E_DEBUG_TLBCACHE
    g_s2e->getDebugStream(g_s2e_state.get()) << "updateTlbEntry: replacing " << hexval(oldObjectState) << " with "
                                             << hexval(newObjectState) << " (" << mmu_idx << ',' << index << ")\n";
#endif

    if (oldObjectState != newObjectState) {
        flushTlbCachePage(oldObjectState, mmu_idx, index);
        if (!g_s2e_single_path_mode) {
            m_tlbMap[newObjectState].push_back(TlbCoordinates(mmu_idx, index));
        }
    }

#ifdef S2E_DEBUG_TLBCACHE
    const ObjectStateTlbReferences &refs = m_tlbMap[const_cast<ObjectState *>(newObjectState)];
    for (unsigned i = 0; i < refs.size(); ++i) {
        g_s2e->getDebugStream(g_s2e_state.get()) << "   "
                                                 << " (" << refs[i].first << ',' << refs[i].second << ")\n";
    }
#endif

    /* Update the TLB entry */
    entryObject(cpu, mmu_idx, index) = const_cast<ObjectState *>(newObjectState.get());

    if (newObjectState->isSharedConcrete()) {
        entry->se_addend = (hostAddr - virtAddr);
    } else {
        entry->se_addend = ((uintptr_t) newObjectState->getConcreteBuffer(true) - virtAddr);

        if (m_asCache->isOwnedByUs(newObjectState)) {
            entry->addr_write &= ~TLB_NOT_OURS;
        } else {
            entry->addr_write |= TLB_NOT_OURS;
        }
    }

    updateTlbEntryConcreteStatus(mmu_idx, index, newObjectState);

    if (TlbAudit && !audit()) {
        pabort("TLB cache audit failed");
    }
}

bool S2EExecutionStateTlb::audit() {
    /**
     * Go through the TLB and make sure that all object states are
     * properly referenced.
     */
    CPUState *cpu = m_registers->getCpuCaches();

    for (const auto &[os, refs] : m_tlbMap) {
        for (const auto &[mmu_idx, index] : refs) {
            void *object = entryObject(cpu, mmu_idx, index);
            if (object != os.get()) {
                llvm::errs() << "TLB audit: map entry (" << mmu_idx << "," << index << ") refers to "
                             << hexval(os.get()) << " but the TLB holds " << hexval(object) << "\n";
                return false;
            }
        }
    }

    for (unsigned mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        for (unsigned index = 0; index < tlbSize(cpu, mmu_idx); index++) {
            void *object = entryObject(cpu, mmu_idx, index);
            if (!object) {
                continue;
            }

            auto it = m_tlbMap.find(static_cast<ObjectState *>(object));
            if (it == m_tlbMap.end()) {
                llvm::errs() << "TLB audit: TLB entry (" << mmu_idx << "," << index << ") refers to " << hexval(object)
                             << " which is not in the map\n";
                return false;
            }

            unsigned foundCount = 0;
            for (const auto &coords : it->second) {
                if (coords == TlbCoordinates(mmu_idx, index)) {
                    foundCount++;
                }
            }

            if (foundCount != 1) {
                llvm::errs() << "TLB audit: TLB entry (" << mmu_idx << "," << index << ") is referenced " << foundCount
                             << " times by " << hexval(object) << "\n";
                return false;
            }
        }
    }

    return true;
}
} // namespace s2e
