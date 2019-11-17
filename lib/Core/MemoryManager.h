//===-- MemoryManager.h -----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_MEMORYMANAGER_H
#define KLEE_MEMORYMANAGER_H

#include <stdint.h>
#include <vector>

namespace llvm {
class Value;
}

namespace klee {
class MemoryObject;

class MemoryManager {
private:
    typedef std::vector<MemoryObject *> objects_ty;

public:
    MemoryManager() {
    }
    ~MemoryManager();

    MemoryObject *allocate(uint64_t address, uint64_t size, bool isLocal, bool isGlobal, bool isFixed);
};

} // End klee namespace

#endif
