///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

#include <vector>

#include <klee/Executor.h>
#include <klee/Expr.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Module.h>

namespace s2e {

typedef llvm::SmallVector<klee::ref<klee::Expr>, 5> HandlerArgs;

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
} // namespace s2e
