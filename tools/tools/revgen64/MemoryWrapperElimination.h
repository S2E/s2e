///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef REVGEN_MEM_ELIM_H

#define REVGEN_MEM_ELIM_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <Translator/Translator.h>
#include <lib/Utils/Log.h>

namespace s2etools {

class MemoryWrapperElimination : public llvm::ModulePass {
    static LogKey TAG;
    static char PID;

    unsigned m_wrappersCount;
    unsigned m_stackPointerCount;
    unsigned m_framePointerCount;

    typedef std::vector<llvm::CallInst *> CallSites;

private:
    void findCallSites(Translator::MemoryWrappers &wrappers, CallSites &cs);
    void eliminateWrappers(const CallSites &cs);

public:
    MemoryWrapperElimination() : llvm::ModulePass(PID) {
        m_wrappersCount = 0;
        m_stackPointerCount = 0;
        m_framePointerCount = 0;
    }
    virtual bool runOnModule(llvm::Module &M);
    virtual const char *getPassName() const {
        return "MemoryWrapperElimination";
    }
};
}

#endif
