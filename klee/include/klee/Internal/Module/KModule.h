//===-- KModule.h -----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_KMODULE_H
#define KLEE_KMODULE_H

#include <klee/Expr.h>

#include <llvm/ADT/DenseMap.h>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "Cell.h"

namespace llvm {
class BasicBlock;
class Constant;
class ConstantExpr;
class Function;
class Instruction;
class Module;
class DataLayout;
class GlobalValue;
} // namespace llvm

namespace klee {
struct Cell;
class Executor;
class Expr;
struct KInstruction;
struct KGEPInstruction;
class KModule;
template <class T> class ref;

using KInstructions = std::vector<KInstruction *>;
using KBasicBlockEntries = std::map<llvm::BasicBlock *, unsigned>;

class KFunction {
private:
    llvm::Function *function;

    unsigned numArgs, numRegisters;

    KInstructions instructions;

    KBasicBlockEntries basicBlockEntry;
    llvm::DenseMap<const llvm::Instruction *, KInstruction *> instrMap;

    KFunction(const KFunction &);
    KFunction &operator=(const KFunction &);

public:
    explicit KFunction(llvm::Function *, KModule *);
    ~KFunction();

    unsigned getArgRegister(unsigned index) {
        return index;
    }

    unsigned getNumArgs() const {
        return numArgs;
    }

    unsigned getNumRegisters() const {
        return numRegisters;
    }

    KInstructions &getInstructions() {
        return instructions;
    }

    KInstruction **getInstructionPtr(unsigned num) {
        assert(num < instructions.size());
        return &instructions[num];
    }

    llvm::Function *getFunction() const {
        return function;
    }

    KInstruction *getInstruction(const llvm::Instruction *instr) const;

    unsigned getBbEntry(llvm::BasicBlock *bb) const {
        auto it = basicBlockEntry.find(bb);
        assert(it != basicBlockEntry.end());
        return (*it).second;
    }
};

using GlobalAddresses = std::unordered_map<const llvm::GlobalValue *, ref<ConstantExpr>>;

using KModulePtr = std::shared_ptr<KModule>;

class KConstant;

class KModule {
private:
    llvm::Module *module;
    llvm::DataLayout *dataLayout;

    // Our shadow versions of LLVM structures.
    std::vector<KFunction *> functions;
    std::map<llvm::Function *, KFunction *> functionMap;

    std::vector<const llvm::Constant *> constants;
    std::map<const llvm::Constant *, KConstant *> constantMap;
    std::vector<Cell> constantTable;

    KModule(llvm::Module *_module);
    KModule() {
    }

    template <typename SqType, typename TypeIt>
    void computeOffsetsSeqTy(const GlobalAddresses &globalAddresses, KGEPInstruction *kgepi,
                             ref<ConstantExpr> &constantOffset, uint64_t index, const TypeIt it);

    template <typename TypeIt>
    void computeOffsets(const GlobalAddresses &globalAddresses, KGEPInstruction *kgepi, TypeIt ib, TypeIt ie);

    /// bindInstructionConstants - Initialize any necessary per instruction
    /// constant values.
    void bindInstructionConstants(const GlobalAddresses &globalAddresses, KInstruction *KI);

    KConstant *getKConstant(const llvm::Constant *c) const;

public:
    ~KModule();

    llvm::Module *getModule() const {
        return module;
    }

    const llvm::DataLayout *getDataLayout() const {
        return dataLayout;
    }

    KFunction *getKFunction(llvm::Function *f) const {
        auto it = functionMap.find(f);
        if (it != functionMap.end()) {
            return (*it).second;
        }
        return nullptr;
    }

    const Cell &getConstant(unsigned idx) const {
        assert(idx < constantTable.size());
        return constantTable[idx];
    }

    /// Initialize local data structures.
    void prepare();

    void buildShadowStructures();

    /// Return an id for the given constant, creating a new one if necessary.
    unsigned getConstantID(llvm::Constant *c, KInstruction *ki);

    /// Update shadow structures for newly added function
    KFunction *updateModuleWithFunction(llvm::Function *f);

    /// Remove function from KModule and call removeFromParend on it
    void removeFunction(llvm::Function *f, bool keepDeclaration = false);

    Expr::Width getWidthForLLVMType(llvm::Type *type) const;

    ref<klee::ConstantExpr> evalConstant(const GlobalAddresses &globalAddresses, const llvm::Constant *c,
                                         const KInstruction *ki = nullptr);

    ref<klee::ConstantExpr> evalConstantExpr(const GlobalAddresses &globalAddresses, const llvm::ConstantExpr *ce,
                                             const KInstruction *ki = nullptr);

    /// bindModuleConstants - Initialize the module constant table.
    void bindModuleConstants(const GlobalAddresses &globalAddresses);

    KFunction *bindFunctionConstants(GlobalAddresses &globalAddresses, llvm::Function *f);

    static KModulePtr create(llvm::Module *module) {
        return KModulePtr(new KModule(module));
    }

    void outputModule(llvm::raw_ostream &os);

    void outputSource(llvm::raw_ostream &os, bool noTruncatedSourceLines);
};
} // namespace klee

#endif
