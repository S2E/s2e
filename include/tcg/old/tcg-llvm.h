/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2017, Cyberhaven
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TCG_LLVM_H
#define TCG_LLVM_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

//#include "tcg.h"

/*****************************/
/* Functions for QEMU c code */

struct TCGLLVMContext;

extern struct TCGLLVMContext *tcg_llvm_ctx;

struct TCGLLVMRuntime {
    // NOTE: The order of these are fixed !
    uint64_t helper_ret_addr;
    uint64_t helper_call_addr;
    uint64_t helper_regs[3];
// END of fixed block

#ifdef CONFIG_SYMBEX
    /* run-time tb linking mechanism */
    uint8_t goto_tb;
#endif

#ifndef CONFIG_SYMBEX
    uint64_t last_opc_index;
    uint64_t last_pc;
#endif
};

extern struct TCGLLVMRuntime tcg_llvm_runtime;

struct TCGLLVMContext *tcg_llvm_initialize(void);
void tcg_llvm_close(struct TCGLLVMContext *l);

struct TCGContext;

void *tcg_llvm_gen_code(struct TCGLLVMContext *l, struct TCGContext *s);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

/***********************************/
/* External interface for C++ code */

// Undefine cat from "compiler.h"
#undef cat

namespace llvm {
class Function;
class FunctionType;
class LLVMContext;
class Module;
class ModuleProvider;
class StoreInst;
class ReturnInst;
class BasicBlock;

namespace legacy {
class FunctionPassManager;
}
}

#ifdef STATIC_TRANSLATOR
#include <llvm/ADT/SmallVector.h>

struct TCGLLVMTBInfo {
    /* Return instructions */
    llvm::SmallVector<llvm::ReturnInst *, 2> returnInstructions;

    /* Instructions that assign a value to the program counter */
    llvm::SmallVector<llvm::StoreInst *, 4> pcAssignments;

    llvm::SmallVector<uint64_t, 2> staticBranchTargets;

    void clear() {
        returnInstructions.clear();
        pcAssignments.clear();
        staticBranchTargets.clear();
    }
};
#endif

struct TCGLLVMContextPrivate;

struct TCGLLVMContext {
private:
    TCGLLVMContextPrivate *m_private;

public:
    TCGLLVMContext(llvm::LLVMContext &);
    ~TCGLLVMContext();

    llvm::LLVMContext &getLLVMContext();

    llvm::Module *getModule();
    llvm::ModuleProvider *getModuleProvider();

    llvm::legacy::FunctionPassManager *getFunctionPassManager() const;

#ifdef CONFIG_SYMBEX
    /** Called after linking all helper libraries */
    void initializeHelpers();
    void initializeNativeCpuState();
    bool isInstrumented(llvm::Function *tb);
#endif

    static bool GetStaticBranchTarget(const llvm::BasicBlock *bb, uint64_t *target);

    llvm::Function *generateCode(struct TCGContext *s);

#ifdef STATIC_TRANSLATOR
    const TCGLLVMTBInfo &getTbInfo() const;
    llvm::Function *createTbFunction(const std::string &name);
    llvm::FunctionType *getTbType();
#endif
};

#endif

#endif
