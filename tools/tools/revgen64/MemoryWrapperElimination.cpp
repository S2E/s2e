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

#include <llvm/ADT/SmallVector.h>

#include <lib/Utils/Utils.h>

#include "MemoryWrapperElimination.h"

using namespace llvm;

namespace s2etools {

LogKey MemoryWrapperElimination::TAG = LogKey("MemoryWrapperElimination");
char MemoryWrapperElimination::PID;

static bool GetLeafGpRegisterLoads(Instruction *I, SmallVector<LoadInst *, 1> &leafs) {
    LoadInst *load = dyn_cast<LoadInst>(I);
    if (load) {
        if (!Translator::isGpRegister(load->getPointerOperand())) {
            return false;
        }

        leafs.push_back(load);
        return true;
    }

    if (I->getOpcode() != Instruction::Add) {
        return false;
    }

    /* Check for instructions of the form %tmp2_v = add i32 %esp_v, -4 */
    ConstantInt *offset = dyn_cast<ConstantInt>(I->getOperand(1));
    if (!offset) {
        return false;
    }

    I = dyn_cast<Instruction>(I->getOperand(0));
    if (!I) {
        return false;
    }

    return GetLeafGpRegisterLoads(I, leafs);
}

void MemoryWrapperElimination::eliminateWrappers(const CallSites &cs) {
    for (auto const &ci : cs) {
        Value *ptr = ci->getOperand(1);

        MDNode *metadata = ci->getMetadata("s2e.pc");

        bool isLoad = ci->getNumOperands() == 4;

        if (isLoad) {
            Type *memTy = ci->getCalledFunction()->getReturnType()->getPointerTo();
            LOGDEBUG(*ptr << " - " << *memTy << "\n");
            ptr = new IntToPtrInst(ptr, memTy, "", ci);
            LoadInst *load = new LoadInst(ptr, "", ci);
            ci->replaceAllUsesWith(load);
            if (metadata) {
                load->setMetadata("s2e.pc", metadata);
            }
        } else {
            Value *val = ci->getOperand(2);
            Type *memTy = val->getType()->getPointerTo();
            LOGDEBUG(*ci << " - " << *ptr << " - " << *memTy << "\n");
            ptr = new IntToPtrInst(ptr, memTy, "", ci);
            StoreInst *si = new StoreInst(val, ptr, ci);
            if (metadata) {
                si->setMetadata("s2e.pc", metadata);
            }
            ci->eraseFromParent();
        }
    }
}

void MemoryWrapperElimination::findCallSites(Translator::MemoryWrappers &wrappers, CallSites &cs) {
    for (auto const &wrapper : wrappers) {
        for (auto uit = wrapper->use_begin(); uit != wrapper->use_end(); ++uit) {
            CallInst *ci = dyn_cast<CallInst>(uit->get());
            if (!ci) {
                continue;
            }

            ++m_wrappersCount;

            Instruction *ptr = dyn_cast<Instruction>(ci->getOperand(0));
            if (!ptr) {
                continue;
            }

            SmallVector<LoadInst *, 1> leafs;
            if (!GetLeafGpRegisterLoads(ptr, leafs) || leafs.size() != 1) {
                continue;
            }

            LoadInst *regLoad = leafs[0];
            Value *gep = regLoad->getPointerOperand();
            /* Figure out if the pointer is derived from the esp register */
            if (Translator::isGpRegister(gep, X86Translator::REG_ESP)) {
                m_stackPointerCount++;
                cs.push_back(ci);
            } else if (Translator::isGpRegister(gep, X86Translator::REG_EBP)) {
                m_framePointerCount++;
                cs.push_back(ci);
            }
        }
    }
}

bool MemoryWrapperElimination::runOnModule(llvm::Module &M) {
    Translator::MemoryWrappers loads, stores;

    Translator::getLoadWrappers(M, loads);
    Translator::getStoreWrappers(M, stores);

    CallSites cs;

    findCallSites(loads, cs);
    findCallSites(stores, cs);

    LOGDEBUG("Found " << cs.size() << "/" << m_wrappersCount << " memory wrappers to optimize\n");

    eliminateWrappers(cs);

    return true;
}
} // namespace s2etools
