///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_EXECUTION_STATE_TLB

#define S2E_EXECUTION_STATE_TLB

#include <klee/Memory.h>
#include <unordered_map>
#include <vector>
#include "AddressSpaceCache.h"
#include "S2EExecutionStateRegisters.h"

extern "C" {
struct CPUX86State;
}

namespace s2e {

class S2EExecutionStateTlb {
public:
    /**
     * The following tracks the location of every ObjectState
     * in the TLB in order to optimize TLB updates.
     */
    typedef std::pair<unsigned int, unsigned int> TlbCoordinates;
    typedef llvm::SmallVector<TlbCoordinates, 8> ObjectStateTlbReferences;
    typedef std::unordered_map<klee::ObjectStateConstPtr, ObjectStateTlbReferences, klee::ObjectStatePtrHash> TlbMap;

private:
    TlbMap m_tlbMap;
    AddressSpaceCache *m_asCache;
    S2EExecutionStateRegisters *m_registers;

public:
    S2EExecutionStateTlb(AddressSpaceCache *ascache, S2EExecutionStateRegisters *regs)
        : m_asCache(ascache), m_registers(regs) {
    }

    void assignNewState(AddressSpaceCache *ascache, S2EExecutionStateRegisters *regs) {
        m_asCache = ascache;
        m_registers = regs;
    }

    /* Change all entries that refer to oldState to newState */
    void updateTlb(const klee::ObjectStateConstPtr &oldState, const klee::ObjectStatePtr &newState);

    void addressSpaceChangeUpdateTlb(const klee::ObjectStateConstPtr &oldState, const klee::ObjectStatePtr &newState);

    void flushTlbCache();

    void flushTlbCachePage(const klee::ObjectStatePtr &objectState, int mmu_idx, int index);

    void updateTlbEntryConcreteStatus(struct CPUX86State *env, unsigned mmu_idx, unsigned index,
                                      const klee::ObjectStateConstPtr &state);

#if defined(SE_ENABLE_PHYSRAM_TLB)
    void updateRamTlb(const klee::ObjectStateConstPtr &oldState, const klee::ObjectStatePtr &newState);
    void clearRamTlb();
#endif

    void clearTlbOwnership();

    void updateTlbEntry(struct CPUX86State *env, int mmu_idx, uint64_t virtAddr, uint64_t hostAddr);

    bool audit();
};
} // namespace s2e

#endif
