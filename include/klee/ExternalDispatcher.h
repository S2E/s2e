//===-- ExternalDispatcher.h ------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXTERNALDISPATCHER_H
#define KLEE_EXTERNALDISPATCHER_H

#include <map>
#include <stdint.h>
#include <string>
#include <vector>

namespace llvm {
class ExecutionEngine;
class Instruction;
class Function;
class FunctionType;
class Module;
class LLVMContext;
}

namespace klee {
class ExternalDispatcher {
private:
    llvm::LLVMContext &context;

    llvm::ExecutionEngine *compileModule(llvm::Module *M);
    llvm::Module *getModuleForNewFunction(const llvm::Function *F);

protected:
    typedef std::map<const llvm::Instruction *, llvm::Function *> dispatchers_ty;
    dispatchers_ty dispatchers;

    static uint64_t *gTheArgsP;

    std::map<llvm::Module *, llvm::ExecutionEngine *> executionEngines;
    std::map<std::string, void *> preboundFunctions;

    llvm::Function *createDispatcher(llvm::Function *f, llvm::Instruction *i);
    virtual bool runProtectedCall(llvm::Function *f, uint64_t *args);

    llvm::ExecutionEngine *getExecutionEngine(llvm::Function *func);

public:
    ExternalDispatcher(llvm::LLVMContext &context);
    virtual ~ExternalDispatcher();

    /* Call the given function using the parameter passing convention of
     * ci with arguments in args[1], args[2], ... and writing the result
     * into args[0].
     */
    virtual bool executeCall(llvm::Function *function, llvm::Instruction *i, uint64_t *args);
    virtual void *resolveSymbol(const std::string &name);
};
}

#endif
