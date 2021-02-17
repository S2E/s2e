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
#include "klee/Interpreter.h"

#include <llvm/ADT/DenseMap.h>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

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
class InterpreterHandler;
class InstructionInfoTable;
struct KInstruction;
class KModule;
template <class T> class ref;

struct KFunction {
    llvm::Function *function;

    unsigned numArgs, numRegisters;

    unsigned numInstructions;
    KInstruction **instructions;

    std::map<llvm::BasicBlock *, unsigned> basicBlockEntry;
    llvm::DenseMap<const llvm::Instruction *, KInstruction *> instrMap;

    /// Whether instructions in this function should count as
    /// "coverable" for statistics and search heuristics.
    bool trackCoverage;

private:
    KFunction(const KFunction &);
    KFunction &operator=(const KFunction &);

public:
    explicit KFunction(llvm::Function *, KModule *);
    ~KFunction();

    unsigned getArgRegister(unsigned index) {
        return index;
    }
};

class KConstant {
public:
    /// Actual LLVM constant this represents.
    llvm::Constant *ct;

    /// The constant ID.
    unsigned id;

    /// First instruction where this constant was encountered, or NULL
    /// if not applicable/unavailable.
    KInstruction *ki;

    KConstant(llvm::Constant *, unsigned, KInstruction *);
};

using GlobalAddresses = std::unordered_map<const llvm::GlobalValue *, ref<ConstantExpr>>;

using KModulePtr = std::shared_ptr<KModule>;

class KModule {
public:
    llvm::Module *module;
    llvm::DataLayout *dataLayout;

    // Our shadow versions of LLVM structures.
    std::vector<KFunction *> functions;
    std::map<llvm::Function *, KFunction *> functionMap;

    std::vector<const llvm::Constant *> constants;
    std::map<const llvm::Constant *, KConstant *> constantMap;
    KConstant *getKConstant(const llvm::Constant *c);

    std::vector<Cell> constantTable;

private:
    KModule(llvm::Module *_module);
    KModule() {
    }

public:
    ~KModule();

    /// Initialize local data structures.
    //
    // FIXME: ihandler should not be here
    void prepare(const Interpreter::ModuleOptions &opts, InterpreterHandler *ihandler);

    void buildShadowStructures();

    void linkLibraries(const Interpreter::ModuleOptions &opts);

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

    static KModulePtr create(llvm::Module *module) {
        return KModulePtr(new KModule(module));
    }
};
} // namespace klee

#endif
