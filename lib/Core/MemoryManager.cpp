//===-- MemoryManager.cpp -------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/CoreStats.h"
#include "klee/Memory.h"
#include "MemoryManager.h"

#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Solver.h"

#include "llvm/Support/CommandLine.h"

using namespace klee;

namespace {
llvm::cl::opt<bool> DeterministicAllocation("allocate-determ",
                                            llvm::cl::desc("Allocate memory deterministically(default=off)"),
                                            llvm::cl::init(false));

llvm::cl::opt<unsigned>
    DeterministicAllocationSize("allocate-determ-size",
                                llvm::cl::desc("Preallocated memory for deterministic allocation in MB (default=100)"),
                                llvm::cl::init(100));

llvm::cl::opt<bool> NullOnZeroMalloc("return-null-on-zero-malloc",
                                     llvm::cl::desc("Returns NULL in case malloc(size) was "
                                                    "called with size 0 (default=off)."),
                                     llvm::cl::init(false));

llvm::cl::opt<unsigned> RedZoneSpace("red-zone-space",
                                     llvm::cl::desc("Set the amount of free space between allocations. This is "
                                                    "important to detect out-of-bound accesses (default=10)."),
                                     llvm::cl::init(10));

llvm::cl::opt<unsigned long long>
    DeterministicStartAddress("allocate-determ-start-address",
                              llvm::cl::desc("Start address for deterministic allocation. Has to be page "
                                             "aligned (default=0x7ff30000000)."),
                              llvm::cl::init(0x7ff30000000));
}

/***/
MemoryManager::~MemoryManager() {
    while (!objects.empty()) {
        MemoryObject *mo = objects.back();
        objects.pop_back();
        delete mo;
    }
}

MemoryObject *MemoryManager::allocate(uint64_t size, bool isLocal, bool isGlobal, const llvm::Value *allocSite) {
    if (size > 10 * 1024 * 1024) {
        klee_warning_once(0, "failing large alloc: %u bytes", (unsigned) size);
        return 0;
    }
    uintptr_t address = (uintptr_t) malloc((unsigned) size);
    if (!address)
        return 0;

    ++stats::allocations;
    MemoryObject *res = new MemoryObject(address, size, isLocal, isGlobal, false, allocSite);
    objects.push_back(res);
    return res;
}

MemoryObject *MemoryManager::allocateFixed(uint64_t address, uint64_t size, const llvm::Value *allocSite) {
    ++stats::allocations;
    MemoryObject *res = new MemoryObject(address, size, false, true, true, allocSite);
    objects.push_back(res);
    return res;
}

void MemoryManager::deallocate(const MemoryObject *mo) {
    assert(0);
}

void MemoryManager::markFreed(MemoryObject *mo) {
    objects_ty::iterator mo_it = std::find(objects.begin(), objects.end(), mo);
    if (mo_it != objects.end()) {
        if (!mo->isFixed && !DeterministicAllocation)
            free((void *) mo->address);
        objects.erase(mo_it);
    }
}

size_t MemoryManager::getUsedDeterministicSize() {
    return nextFreeSlot - deterministicSpace;
}
