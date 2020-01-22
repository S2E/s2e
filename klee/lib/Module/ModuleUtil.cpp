//===-- ModuleUtil.cpp ----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/Support/ModuleUtil.h"
#include <klee/Common.h>

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

using namespace llvm;
using namespace klee;

Module *klee::linkWithLibrary(Module *module, const std::string &libraryName) {
    auto ErrorOrMemBuff = MemoryBuffer::getFile(libraryName);
    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        pabort("Reading library failed!");
    }

    auto ErrorOrMod = parseBitcodeFile(ErrorOrMemBuff.get()->getMemBufferRef(), module->getContext());

    Linker linker(*module);

    if (linker.linkInModule(std::move(ErrorOrMod.get()))) {
        pabort("linking in library failed!");
    }

    return module;
}

Function *klee::getDirectCallTarget(const Instruction *i) {
    assert(isa<CallInst>(i) || isa<InvokeInst>(i));

    Value *v = i->getOperand(0);
    if (Function *f = dyn_cast<Function>(v)) {
        return f;
    } else if (llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(v)) {
        if (ce->getOpcode() == Instruction::BitCast)
            if (Function *f = dyn_cast<Function>(ce->getOperand(0)))
                return f;

        // NOTE: This assert may fire, it isn't necessarily a problem and
        // can be disabled, I just wanted to know when and if it happened.
        pabort("FIXME: Unresolved direct target for a constant expression.");
    }

    return 0;
}

static bool valueIsOnlyCalled(const Value *v) {
    for (Value::const_use_iterator it = v->use_begin(), ie = v->use_end(); it != ie; ++it) {
        if (const Instruction *instr = dyn_cast<Instruction>(*it)) {
            if (instr->getOpcode() == 0)
                continue; // XXX function numbering inst
            if (!isa<CallInst>(instr) && !isa<InvokeInst>(instr))
                return false;

            // Make sure that the value is only the target of this call and
            // not an argument.
            for (unsigned i = 1, e = instr->getNumOperands(); i != e; ++i)
                if (instr->getOperand(i) == v)
                    return false;
        } else if (const llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(*it)) {
            if (ce->getOpcode() == Instruction::BitCast)
                if (valueIsOnlyCalled(ce))
                    continue;
            return false;
        } else if (const GlobalAlias *ga = dyn_cast<GlobalAlias>(*it)) {
            // XXX what about v is bitcast of aliasee?
            if (v == ga->getAliasee() && !valueIsOnlyCalled(ga))
                return false;
        } else {
            return false;
        }
    }

    return true;
}

bool klee::functionEscapes(const Function *f) {
    return !valueIsOnlyCalled(f);
}
