///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#include <Translator/Translator.h>
#include <lib/Utils/Utils.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>

#include "RegisterPromotion.h"

using namespace llvm;

namespace {
cl::opt<bool> UnsafeOptimizations("unsafe-reg-opt",
                                  cl::desc("Unsafe optimizations when promoting cpu registers to llvm variables"),
                                  cl::init(false), cl::Optional);
}

namespace s2etools {

LogKey RegisterPromotion::TAG = LogKey("RegisterPromotion");
char RegisterPromotion::PID;

bool RegisterPromotion::isReturnRegister(GetElementPtrInst *gep) {
    unsigned reg;
    if (!Translator::isGpRegister(gep, &reg)) {
        return false;
    }

    /* EDX is used for 64-bit values */
    return reg == X86Translator::REG_EAX || reg == X86Translator::REG_EDX;
}

void RegisterPromotion::findInstructions(Function &F, GEPs &geps, Calls &calls, Returns &rets) {
    foreach2 (bbit, F.begin(), F.end()) {
        BasicBlock &bb = *bbit;
        foreach2 (iit, bb.begin(), bb.end()) {
            Instruction *i = &*iit;
            GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(i);
            if (gep) {
                if (Translator::isGpRegister(gep) || Translator::isPcRegister(gep)) {
                    geps.push_back(gep);
                }
                continue;
            }

            CallInst *ci = dyn_cast<CallInst>(i);
            if (ci) {
                Function *f = ci->getCalledFunction();
                // For now, also spill regs for normal function calls
                // Except for loads and stores
                if (!f->getName().startswith("__")) {
                    calls.push_back(ci);
                }
                continue;
            }

            ReturnInst *ri = dyn_cast<ReturnInst>(i);
            if (ri) {
                rets.push_back(ri);
            }
        }
    }
}

static uint64_t GetGepIndex(GetElementPtrInst *gep) {
    // XXX: many assumptions here about the structure of cpu reg gep
    // In particualar, that there are no more than 32 registers
    unsigned ret = 1;
    for (unsigned i = 0; i < gep->getNumIndices(); ++i) {
        ConstantInt *ci = dyn_cast<ConstantInt>(gep->getOperand(i + 1));
        ret = ret * 32 + ci->getZExtValue();
    }
    return ret;
}

void RegisterPromotion::createAllocas(Function &F, GEPs &geps, Calls &calls, Returns &rets) {
    LLVMContext &ctx = F.getParent()->getContext();
    IRBuilder<> builder(ctx);
    BasicBlock *bb = &*(F.begin());

    // Need to increment bb because first instruction is a gep
    BasicBlock::iterator bbit = bb->begin();
    while (bbit != bb->end() && !dyn_cast<GetElementPtrInst>(&*bbit)) {
        ++bbit;
    }
    assert(bbit != bb->end());
    ++bbit;

    builder.SetInsertPoint(bb, bbit);

    DenseMap<uint64_t, GEPs> uniqueGeps;
    for (auto const &gep : geps) {
        uint64_t index = GetGepIndex(gep);
        uniqueGeps[index].push_back(gep);
        LOGDEBUG("Adding GEP " << hexval(index) << " " << *gep << "\n");
    }

    DenseSet<Instruction *> toErase;

    for (auto const uniqueGep : uniqueGeps) {
        const GEPs &dups = uniqueGep.second;
        assert(dups.size() >= 1);

        LOGDEBUG("GEP " << hexval(uniqueGep.first) << " cnt: " << dups.size() << "\n");

        GetElementPtrInst *gep = dups[0];
        AllocaInst *alloca = builder.CreateAlloca(gep->getType());
        Value *newgep = builder.Insert(gep->clone());
        Value *ld = builder.CreateLoad(newgep);
        builder.CreateStore(ld, alloca);

        for (auto const &dgep : dups) {
            dgep->replaceAllUsesWith(alloca);
            toErase.insert(dgep);
        }

        uint64_t bitmask = Translator::getRegisterBitMask(gep);

        /* Spill the register before calling a function and read back after calling it */
        for (auto const &ci : calls) {
            bool doSave = true;
            bool doRestore = true;

            Function *f = ci->getCalledFunction();
            auto mask = Translator::getRegisterMaskForHelper(f);

            doSave = mask.rmask & bitmask;
            doRestore = mask.wmask & bitmask;

            if (doSave) {
                Instruction *li = new LoadInst(alloca, "", ci);
                new StoreInst(li, newgep, ci);
            }

            if (doRestore && (!UnsafeOptimizations || isReturnRegister(gep))) {
                // XXX: we don't restore esp, figure out calling convention
                Instruction *li = new LoadInst(newgep);
                li->insertAfter(ci);

                Instruction *si = new StoreInst(li, alloca);
                si->insertAfter(li);
            }
        }

        /* Sill all the regs before the function returns */
        for (auto const &ri : rets) {
            if (!UnsafeOptimizations || isReturnRegister(gep)) {
                Instruction *li = new LoadInst(alloca, "", ri);
                new StoreInst(li, newgep, ri);
            }
        }
    }

    for (auto const &e : toErase) {
        e->eraseFromParent();
    }
}

bool RegisterPromotion::runOnFunction(Function &F) {
    if (!m_toPromote.count(&F)) {
        return false;
    }

    GEPs geps;
    Calls calls;
    Returns rets;

    findInstructions(F, geps, calls, rets);

    LOGDEBUG(F.getName() << ": " << geps.size() << " geps and " << calls.size() << " helper calls\n");

    createAllocas(F, geps, calls, rets);

    verifyFunction(F);

    return true;
}
} // namespace s2etools
