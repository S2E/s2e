///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    virtual const char *getPassName() const {
        return "InstructionLabeling";
    }

private:
};
}

#endif
