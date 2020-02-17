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
    virtual llvm::StringRef getPassName() const {
        return "MemoryWrapperElimination";
    }
};
} // namespace s2etools

#endif
