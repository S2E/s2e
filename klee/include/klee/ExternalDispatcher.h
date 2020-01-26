//===-- ExternalDispatcher.h ------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXTERNALDISPATCHER_H
#define KLEE_EXTERNALDISPATCHER_H

#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#include <llvm/ADT/SmallVector.h>

namespace klee {
class ExternalDispatcher {
private:
public:
    typedef uint64_t (*external_fcn_t)(...);
    typedef llvm::SmallVector<uint64_t, 8> Arguments;

    ExternalDispatcher();
    virtual ~ExternalDispatcher();

    virtual void *resolveSymbol(const std::string &name);
    virtual bool call(external_fcn_t targetFunction, const Arguments &args, uint64_t *result, std::stringstream &err);
};
} // namespace klee

#endif
