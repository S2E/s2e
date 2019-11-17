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

namespace klee {

/***/
MemoryManager::~MemoryManager() {
    while (!objects.empty()) {
        MemoryObject *mo = objects.back();
        objects.pop_back();
        delete mo;
    }
}

MemoryObject *MemoryManager::allocate(uint64_t size, bool isLocal, bool isGlobal) {
    if (size > 10 * 1024 * 1024) {
        klee_warning_once(0, "failing large alloc: %u bytes", (unsigned) size);
        return 0;
    }
    uintptr_t address = (uintptr_t) malloc((unsigned) size);
    if (!address)
        return 0;

    ++stats::allocations;
    MemoryObject *res = new MemoryObject(address, size, isLocal, isGlobal, false);
    objects.push_back(res);
    return res;
}

MemoryObject *MemoryManager::allocateFixed(uint64_t address, uint64_t size) {
    ++stats::allocations;
    MemoryObject *res = new MemoryObject(address, size, false, true, true);
    objects.push_back(res);
    return res;
}

void MemoryManager::deallocate(const MemoryObject *mo) {
    assert(0);
}

void MemoryManager::markFreed(MemoryObject *mo) {
    objects_ty::iterator mo_it = std::find(objects.begin(), objects.end(), mo);
    if (mo_it != objects.end()) {
        if (!mo->isFixed) {
            free((void *) mo->address);
        }
        objects.erase(mo_it);
    }
}
}
