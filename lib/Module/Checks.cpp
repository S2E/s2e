//===-- Checks.cpp --------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Passes.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;
using namespace klee;

char DivCheckPass::ID;

bool DivCheckPass::runOnModule(Module &M) {
    Function *divZeroCheckFunction = 0;

    bool moduleChanged = false;

    LLVMContext &context = M.getContext();

    for (Module::iterator f = M.begin(), fe = M.end(); f != fe; ++f) {
        for (Function::iterator b = f->begin(), be = f->end(); b != be; ++b) {
            for (BasicBlock::iterator i = b->begin(), ie = b->end(); i != ie; ++i) {
                if (BinaryOperator *binOp = dyn_cast<BinaryOperator>(i)) {
                    // find all [s|u][div|mod] instructions
                    Instruction::BinaryOps opcode = binOp->getOpcode();
                    if (opcode == Instruction::SDiv || opcode == Instruction::UDiv || opcode == Instruction::SRem ||
                        opcode == Instruction::URem) {

                        CastInst *denominator = CastInst::CreateIntegerCast(i->getOperand(1), Type::getInt64Ty(context),
                                                                            false, /* sign doesn't matter */
                                                                            "int_cast_to_i64", &*i);

                        // Lazily bind the function to avoid always importing it.
                        if (!divZeroCheckFunction) {
                            Constant *fc = M.getOrInsertFunction("klee_div_zero_check", Type::getVoidTy(context),
                                                                 Type::getInt64Ty(context), NULL);
                            divZeroCheckFunction = cast<Function>(fc);
                        }

                        CallInst *ci = CallInst::Create(divZeroCheckFunction, denominator, "", &*i);

                        // Set debug location of checking call to that of the div/rem
                        // operation so error locations are reported in the correct
                        // location.
                        ci->setDebugLoc(binOp->getDebugLoc());
                        moduleChanged = true;
                    }
                }
            }
        }
    }
    return moduleChanged;
}
