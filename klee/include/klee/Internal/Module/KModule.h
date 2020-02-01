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

#include "klee/Interpreter.h"

#include <llvm/ADT/DenseMap.h>
#include <map>
#include <set>
#include <vector>

namespace llvm {
class BasicBlock;
class Constant;
class Function;
class Instruction;
class Module;
class DataLayout;
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

class KModule {
public:
    llvm::Module *module;
    llvm::DataLayout *dataLayout;

    // Some useful functions to know the address of
    llvm::Function *dbgStopPointFn, *kleeMergeFn;

    // Our shadow versions of LLVM structures.
    std::vector<KFunction *> functions;
    std::map<llvm::Function *, KFunction *> functionMap;

    // Functions which escape (may be called indirectly)
    // XXX change to KFunction
    std::set<llvm::Function *> escapingFunctions;

    std::vector<const llvm::Constant *> constants;
    std::map<const llvm::Constant *, KConstant *> constantMap;
    KConstant *getKConstant(const llvm::Constant *c);

    std::vector<Cell> constantTable;

public:
    KModule(llvm::Module *_module);
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
};
} // namespace klee

#endif
