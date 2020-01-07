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
#include <tcg/tcg.h>

#ifdef __cplusplus
extern "C" {
#endif

// Functions for QEMU C code
extern void *tcg_llvm_translator;

void tcg_llvm_close(void *l);
void *tcg_llvm_gen_code(void *llvmTranslator, struct TCGContext *s, struct TranslationBlock *tb);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <unordered_map>

// External interface for C++ code

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Threading.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>

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

class TCGLLVMTranslator {
private:
    const std::string m_bitcodeLibraryPath;
    std::unique_ptr<llvm::Module> m_module;

    llvm::IRBuilder<> m_builder;

    /* Function pass manager (used for optimizing the code) */
    llvm::legacy::FunctionPassManager *m_functionPassManager;

#ifdef CONFIG_SYMBEX
    /* Declaration of a wrapper function for helpers */
    llvm::Function *m_helperForkAndConcretize;
    llvm::Function *m_qemu_ld_helpers[5];
    llvm::Function *m_qemu_st_helpers[5];
#endif

#ifdef STATIC_TRANSLATOR
    TCGLLVMTBInfo m_info;
#endif

    /* Count of generated translation blocks */
    int m_tbCount;

    /* XXX: The following members are "local" to generateCode method */

    /* TCGContext for current translation block */
    TCGContext *m_tcgContext;

    TranslationBlock *m_tb;

    /* Function for current translation block */
    llvm::Function *m_tbFunction;

    /* Current temp m_values */
    llvm::Value *m_values[TCG_MAX_TEMPS];

    /* Pointers to in-memory versions of globals or local temps */
    llvm::Value *m_memValuesPtr[TCG_MAX_TEMPS];

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    std::unordered_map<TCGLabel *, llvm::BasicBlock *> m_labels;

    llvm::FunctionType *m_tbType;
    llvm::Type *m_cpuType;
    llvm::Value *m_cpuState;
    // Represents CPU state pointer cast to an int
    llvm::Instruction *m_cpuStateInt;

    // This instruction is a no-op in the entry block, we use it
    // in order to simplify instruction insertion.
    llvm::Instruction *m_noop;
    llvm::Value *m_eip;
    llvm::Value *m_ccop;

    static unsigned m_eip_last_gep_index;

    typedef llvm::DenseMap<std::pair<unsigned, unsigned>, llvm::Instruction *> GepMap;
    GepMap m_registers;

    std::string generateName();

    TCGLLVMTranslator(const std::string &bitcodeLibraryPath, std::unique_ptr<llvm::Module> module);

#ifdef CONFIG_SYMBEX
    void initializeNativeCpuState();
    void initializeHelpers();
#endif

public:
    ~TCGLLVMTranslator();

    static TCGLLVMTranslator *create(const std::string &bitcodeLibraryPath);

    llvm::LLVMContext &getContext() const {
        return m_module->getContext();
    }

    llvm::Module *getModule() const {
        return m_module.get();
    }

    const std::string &getBitcodeLibraryPath() const {
        return m_bitcodeLibraryPath;
    }

    llvm::legacy::FunctionPassManager *getFunctionPassManager() const {
        return m_functionPassManager;
    }

    bool isInstrumented(llvm::Function *tb);

    /* Shortcuts */
    llvm::Type *intType(int w) {
        return llvm::IntegerType::get(getContext(), w);
    }
    llvm::Type *intPtrType(int w) {
        return llvm::PointerType::get(intType(w), 0);
    }
    llvm::Type *wordType() {
        return intType(TCG_TARGET_REG_BITS);
    }
    llvm::Type *wordType(int bits) {
        return intType(bits);
    }
    llvm::Type *wordPtrType() {
        return intPtrType(TCG_TARGET_REG_BITS);
    }
    llvm::FunctionType *tbType();

    void adjustTypeSize(unsigned target, llvm::Value **v1);

    llvm::Value *generateCpuStatePtr(uint64_t arg, unsigned sizeInBytes);
    void generateQemuCpuLoad(const TCGArg *args, unsigned memBits, unsigned regBits, bool signExtend);
    void generateQemuCpuStore(const TCGArg *args, unsigned memBits, llvm::Value *valueToStore);

#ifdef STATIC_TRANSLATOR
    uint64_t m_currentPc;
    void attachPcMetadata(llvm::Instruction *instr, uint64_t pc);
#endif
    llvm::Value *attachCurrentPc(llvm::Value *value);

    // This handles the special case of symbolic values
    // assigned to the program counter register
    llvm::Value *handleSymbolicPcAssignment(llvm::Value *orig);

#ifdef STATIC_TRANSLATOR
    bool isPcAssignment(llvm::Value *v) {
        return v == m_eip;
    }

    const TCGLLVMTBInfo &getTbInfo() const {
        return m_info;
    }

    void computeStaticBranchTargets();
#endif

    void adjustTypeSize(unsigned target, llvm::Value **v1, llvm::Value **v2) {
        adjustTypeSize(target, v1);
        adjustTypeSize(target, v2);
    }

    llvm::Type *tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    llvm::Type *tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    /* Helpers */
    llvm::Value *getValue(TCGArg arg);
    void setValue(TCGArg arg, llvm::Value *v);
    void delValue(int idx);

    llvm::Value *getPtrForValue(int idx);
    void delPtrForValue(int idx);
    void initGlobalsAndLocalTemps();
    void loadNativeCpuState(llvm::Function *f);
    unsigned getValueBits(int idx);

    void invalidateCachedMemory();

    uint64_t toInteger(llvm::Value *v) const;

    llvm::BasicBlock *getLabel(TCGArg i);
    void startNewBasicBlock(llvm::BasicBlock *bb = NULL);

    /* Code generation */
    llvm::Value *generateQemuMemOp(bool ld, llvm::Value *value, llvm::Value *addr, int mem_index, int bits);

    int generateOperation(const TCGOp *op);

    llvm::Function *createTbFunction(const std::string &name);
    llvm::Function *generateCode(TCGContext *s, TranslationBlock *tb);
    void removeInterruptExit();

    bool getCpuFieldGepIndexes(unsigned offset, unsigned sizeInBytes, llvm::SmallVector<llvm::Value *, 3> &gepIndexes);
    static bool GetStaticBranchTarget(const llvm::BasicBlock *bb, uint64_t *target);
};

#endif

#endif
