///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
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

#ifndef REVGEN_INST_LABEL_H

#define REVGEN_INST_LABEL_H

#include <llvm/ADT/DenseSet.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <Translator/Translator.h>
#include <lib/Utils/Log.h>

#include <vector>

namespace s2etools {

/**
 * This is a cosmetic pass, it renames virtual variables
 * to make ll files more legible.
 */
class InstructionLabeling : public llvm::FunctionPass {
    static LogKey TAG;
    static char PID;

public:
    InstructionLabeling() : llvm::FunctionPass(PID) {
    }

    virtual bool runOnFunction(llvm::Function &F);
    virtual llvm::StringRef getPassName() const {
        return "InstructionLabeling";
    }

private:
};
} // namespace s2etools

#endif
