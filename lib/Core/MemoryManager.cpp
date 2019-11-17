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
}

MemoryObject *MemoryManager::allocate(uint64_t address, uint64_t size, bool isLocal, bool isFixed) {
    if (size > 10 * 1024 * 1024) {
        klee_warning_once(0, "failing large alloc: %u bytes", (unsigned) size);
        return 0;
    }

    if (!isFixed) {
        if (address) {
            return nullptr;
        }

        address = (uintptr_t) malloc((unsigned) size);
        if (!address) {
            return nullptr;
        }
    }

    ++stats::allocations;
    return new MemoryObject(address, size, isLocal, isFixed);
}
}
