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

#include <iomanip>

#include "klee/LLVMExecutionState.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace klee {

cl::opt<bool> DebugPrintInstructions("debug-print-instructions", cl::desc("Print instructions during execution."),
                                     cl::init(false));

extern cl::opt<bool> DebugLogStateMerge;

LLVMExecutionState::~LLVMExecutionState() {
    while (!stack.empty()) {
        popFrame();
    }
}

Cell &LLVMExecutionState::getArgumentCell(KFunction *kf, unsigned index) {
    return stack.back().locals[kf->getArgRegister(index)];
}

Cell &LLVMExecutionState::getDestCell(KInstruction *target) {
    return stack.back().locals[target->dest];
}

void LLVMExecutionState::stepInstruction() {
    if (DebugPrintInstructions) {
        llvm::errs() << *stats::instructions << " ";
        llvm::errs() << *(pc->inst) << "\n";
    }

    ++*stats::instructions;
    prevPC = pc;
    ++pc;
}

void LLVMExecutionState::transferToBasicBlock(BasicBlock *dst, BasicBlock *src) {
    // Note that in general phi nodes can reuse phi values from the same
    // block but the incoming value is the eval() result *before* the
    // execution of any phi nodes. this is pathological and doesn't
    // really seem to occur, but just in case we run the PhiCleanerPass
    // which makes sure this cannot happen and so it is safe to just
    // eval things in order. The PhiCleanerPass also makes sure that all
    // incoming blocks have the same order for each PHINode so we only
    // have to compute the index once.
    //
    // With that done we simply set an index in the state so that PHI
    // instructions know which argument to eval, set the pc, and continue.

    // XXX this lookup has to go ?
    KFunction *kf = stack.back().kf;
    unsigned entry = kf->getBbEntry(dst);
    pc = kf->getInstructionPtr(entry);
    if (pc->inst->getOpcode() == Instruction::PHI) {
        PHINode *first = static_cast<PHINode *>(pc->inst);
        incomingBBIndex = first->getBasicBlockIndex(src);
    }
}

void LLVMExecutionState::printStack(std::stringstream &msg) const {
    msg << "Stack: \n";
    unsigned idx = 0;
    for (stack_ty::const_reverse_iterator it = stack.rbegin(), ie = stack.rend(); it != ie; ++it) {
        const StackFrame &sf = *it;
        Function *f = sf.kf->getFunction();

        msg << "\t#" << idx++ << " " << std::setw(8) << std::setfill('0') << " in " << f->getName().str() << " (";

        // Yawn, we could go up and print varargs if we wanted to.
        unsigned index = 0;
        for (Function::arg_iterator ai = f->arg_begin(), ae = f->arg_end(); ai != ae; ++ai) {
            if (ai != f->arg_begin())
                msg << ", ";

            msg << ai->getName().str();
            // XXX should go through function
            ref<Expr> value = sf.locals[sf.kf->getArgRegister(index++)].value;
            msg << " [" << state->concolics()->evaluate(value) << "]";
        }
        msg << ")";

        msg << "\n";
    }
}

void LLVMExecutionState::pushFrame(KInstIterator caller, KFunction *kf) {
    stack.push_back(StackFrame(caller, kf));
}

void LLVMExecutionState::popFrame() {
    StackFrame &sf = stack.back();
    for (auto it : sf.allocas) {
        state->addressSpace().unbindObject(it);
    }
    stack.pop_back();
}

void LLVMExecutionState::bindLocal(KInstruction *target, ref<Expr> value) {

    getDestCell(target).value = value;
}

void LLVMExecutionState::bindArgument(KFunction *kf, unsigned index, ref<Expr> value) {
    getArgumentCell(kf, index).value = value;
}

bool LLVMExecutionState::mergeable(const LLVMExecutionState &b) const {
    auto &m = *klee_message_stream;

    if (pc != b.pc) {
        if (DebugLogStateMerge) {
            m << "merge failed: different KLEE pc\n" << *(*pc).inst << "\n" << *(*b.pc).inst << "\n";

            std::stringstream ss;
            printStack(ss);
            b.printStack(ss);
            m << ss.str() << "\n";
        }
        return false;
    }

    {
        auto itA = stack.begin();
        auto itB = b.stack.begin();
        while (itA != stack.end() && itB != b.stack.end()) {
            // XXX vaargs?
            if (itA->caller != itB->caller || itA->kf != itB->kf) {
                if (DebugLogStateMerge) {
                    m << "merge failed: different callstacks" << '\n';
                }
            }
            ++itA;
            ++itB;
        }
        if (itA != stack.end() || itB != b.stack.end()) {
            if (DebugLogStateMerge) {
                m << "merge failed: different callstacks" << '\n';
            }
            return false;
        }
    }

    return true;
}

void LLVMExecutionState::merge(const LLVMExecutionState &b, const ref<Expr> &inA) {
    auto &m = *klee_message_stream;

    // XXX should we have a preference as to which predicate to use?
    // it seems like it can make a difference, even though logically
    // they must contradict each other and so inA => !inB

    int selectCountStack = 0;

    auto itA = stack.begin();
    auto itB = b.stack.begin();
    for (; itA != stack.end(); ++itA, ++itB) {
        StackFrame &af = *itA;
        const StackFrame &bf = *itB;
        for (unsigned i = 0; i < af.kf->getNumRegisters(); i++) {
            ref<Expr> &av = af.locals[i].value;
            const ref<Expr> &bv = bf.locals[i].value;
            if (!av || !bv) {
                // if one is null then by implication (we are at same pc)
                // we cannot reuse this local, so just ignore
            } else {
                av = SelectExpr::create(inA, av, bv);
                selectCountStack += 1;
            }
        }
    }

    if (DebugLogStateMerge) {
        m << "\t\tcreated " << selectCountStack << " select expressions on the stack\n";
    }
}

} // namespace klee