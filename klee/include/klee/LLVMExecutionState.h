///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
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

#ifndef KLEE_LLVMEXECUTIONSTATE_H
#define KLEE_LLVMEXECUTIONSTATE_H

#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstIterator.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Stats/CoreStats.h"

#include "klee/AddressSpace.h"
#include "klee/IExecutionState.h"

namespace klee {

struct StackFrame {
    KInstIterator caller;
    KFunction *kf;

    llvm::SmallVector<ObjectKey, 16> allocas;
    llvm::SmallVector<Cell, 16> locals;

    // For vararg functions: arguments not passed via parameter are
    // stored (packed tightly) in a local (alloca) memory object. This
    // is setup to match the way the front-end generates vaarg code (it
    // does not pass vaarg through as expected). VACopy is lowered inside
    // of intrinsic lowering.
    std::vector<ObjectKey> varargs;

    StackFrame(KInstIterator _caller, KFunction *_kf) : caller(_caller), kf(_kf), varargs(0) {
        locals.resize(kf->getNumRegisters());
    }
};

using stack_ty = llvm::SmallVector<StackFrame, 16>;

class LLVMExecutionState {
public:
    LLVMExecutionState(IExecutionState *state) : state(state) {
    }
    LLVMExecutionState() = delete;
    ~LLVMExecutionState();

    IExecutionState *state = nullptr;

    // pc - pointer to current instruction stream
    KInstIterator pc = nullptr, prevPC = nullptr;
    stack_ty stack;
    unsigned incomingBBIndex = 0;

    void initialize(KFunction *kf) {
        pc = kf->getInstructions();
        pushFrame(0, kf);
    }

    Cell &getArgumentCell(KFunction *kf, unsigned index);
    Cell &getDestCell(KInstruction *target);
    void stepInstruction();
    void transferToBasicBlock(llvm::BasicBlock *dst, llvm::BasicBlock *src);
    void printStack(std::stringstream &msg) const;
    void pushFrame(KInstIterator caller, KFunction *kf);
    void popFrame();
    void bindLocal(KInstruction *target, ref<Expr> value);
    void bindArgument(KFunction *kf, unsigned index, ref<Expr> value);
    bool mergeable(const LLVMExecutionState &b) const;
    void merge(const LLVMExecutionState &b, const ref<Expr> &inA);
};

} // namespace klee

#endif
