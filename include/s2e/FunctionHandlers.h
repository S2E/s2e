///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <vector>

#include <klee/Executor.h>
#include <klee/Expr.h>
#include <llvm/IR/Module.h>

namespace s2e {

void handleForkAndConcretize(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                             std::vector<klee::ref<klee::Expr>> &args);

void handlerAfterMemoryAccess(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                              std::vector<klee::ref<klee::Expr>> &args);

typedef void (*FunctionHandler)(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                                std::vector<klee::ref<klee::Expr>> &arguments);

struct Handler {
    const char *name;
    FunctionHandler handler;
    std::function<llvm::FunctionType *(llvm::Module &)> getOrInsertFunction;
};
}
