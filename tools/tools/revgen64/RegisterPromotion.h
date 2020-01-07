///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef REVGEN_REG_PROM_H

#define REVGEN_REG_PROM_H

#include <llvm/ADT/DenseSet.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <Translator/Translator.h>
#include <lib/Utils/Log.h>

#include <vector>

namespace s2etools {

class RegisterPromotion : public llvm::FunctionPass {
    static LogKey TAG;
    static char PID;

public:
    typedef std::vector<llvm::GetElementPtrInst *> GEPs;
    typedef std::vector<llvm::CallInst *> Calls;
    typedef std::vector<llvm::ReturnInst *> Returns;
    typedef llvm::DenseSet<llvm::Function *> Functions;

    RegisterPromotion(const Functions &f) : llvm::FunctionPass(PID), m_toPromote(f) {
    }

    virtual bool runOnFunction(llvm::Function &F);
    virtual const char *getPassName() const {
        return "RegisterPromotion";
    }

private:
    const Functions &m_toPromote;

    static bool isReturnRegister(llvm::GetElementPtrInst *gep);

    void findInstructions(llvm::Function &F, GEPs &geps, Calls &calls, Returns &rets);
    void createAllocas(llvm::Function &F, GEPs &geps, Calls &calls, Returns &rets);
};
}

#endif
