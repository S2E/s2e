///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <llvm/ADT/SmallVector.h>

#include <lib/Utils/Utils.h>

#include "MemoryWrapperElimination.h"

using namespace llvm;

namespace s2etools {

LogKey MemoryWrapperElimination::TAG = LogKey("MemoryWrapperElimination");
char MemoryWrapperElimination::PID;

static bool GetLeafGpRegisterLoads(Instruction *I, SmallVector<LoadInst *, 1> &leafs) {
    LoadInst *load = dynamic_cast<LoadInst *>(I);
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
    ConstantInt *offset = dynamic_cast<ConstantInt *>(I->getOperand(1));
    if (!offset) {
        return false;
    }

    I = dynamic_cast<Instruction *>(I->getOperand(0));
    if (!I) {
        return false;
    }

    return GetLeafGpRegisterLoads(I, leafs);
}

void MemoryWrapperElimination::eliminateWrappers(const CallSites &cs) {
    for (auto const &ci : cs) {
        Value *ptr = ci->getOperand(0);

        MDNode *metadata = ci->getMetadata("s2e.pc");

        bool isLoad = ci->getNumOperands() == 3;

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
            Value *val = ci->getOperand(1);
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
            CallInst *ci = dynamic_cast<CallInst *>(uit->get());
            if (!ci) {
                continue;
            }

            ++m_wrappersCount;

            Instruction *ptr = dynamic_cast<Instruction *>(ci->getOperand(0));
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
}
