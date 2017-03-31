//===-- Interpreter.h - Abstract Execution Engine Interface -----*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===//

#ifndef KLEE_INTERPRETER_H
#define KLEE_INTERPRETER_H

#include <map>
#include <set>
#include <string>
#include <vector>

struct KTest;

namespace llvm {
class Function;
class Module;
class LLVMContext;
class raw_ostream;

namespace legacy {
class FunctionPassManager;
}
}

namespace klee {
class MemoryObject;
class Array;
class Assignment;
class ConstraintManager;
class ExecutionState;
class Interpreter;
class TimingSolver;

class InterpreterHandler {
public:
    InterpreterHandler() {
    }
    virtual ~InterpreterHandler(){};

    virtual llvm::raw_ostream &getInfoStream() const = 0;

    virtual std::string getOutputFilename(const std::string &filename) = 0;
    virtual llvm::raw_ostream *openOutputFile(const std::string &filename) = 0;

    virtual void incPathsExplored() = 0;

    virtual void processTestCase(const ExecutionState &state, const char *err, const char *suffix) = 0;
};

class Interpreter {
public:
    /// ModuleOptions - Module level options which can be set when
    /// registering a module with the interpreter.
    struct ModuleOptions {
        std::vector<std::string> ExtraLibraries;
        bool Optimize;
        bool CheckDivZero;
        bool Snapshot;
        llvm::legacy::FunctionPassManager *CustomPasses;

        ModuleOptions(const std::vector<std::string> &_ExtraLibraries, bool _Optimize, bool _CheckDivZero,
                      llvm::legacy::FunctionPassManager *_CustomPasses = NULL)
            : ExtraLibraries(_ExtraLibraries), Optimize(_Optimize), CheckDivZero(_CheckDivZero), Snapshot(false),
              CustomPasses(_CustomPasses) {
        }
    };

    /// InterpreterOptions - Options varying the runtime behavior during
    /// interpretation.
    /// TODO: remove this
    struct InterpreterOptions {
        InterpreterOptions() {
        }
    };

protected:
    const InterpreterOptions interpreterOpts;

    Interpreter(const InterpreterOptions &_interpreterOpts) : interpreterOpts(_interpreterOpts){};

public:
    virtual ~Interpreter(){};

    /// Register the module to be executed.
    ///
    /// \return The final module after it has been optimized, checks
    /// inserted, and modified for interpretation.
    virtual const llvm::Module *setModule(llvm::Module *module, const ModuleOptions &opts,
                                          bool createStatsTracker = true) = 0;

    /*** State accessor methods ***/
    virtual bool getSymbolicSolution(TimingSolver *solver,
                                     const std::vector<std::pair<const MemoryObject *, const Array *>> &symbolics,
                                     const ConstraintManager &constraints,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res,
                                     double &queryCost) = 0;
    virtual bool getSymbolicSolution(const std::vector<std::pair<const MemoryObject *, const Array *>> &symbolics,
                                     const Assignment &concolics,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res) = 0;
    virtual bool getSymbolicSolution(const ExecutionState &state,
                                     std::vector<std::pair<std::string, std::vector<unsigned char>>> &res) = 0;
};

} // End klee namespace

#endif
