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
} // namespace llvm

namespace klee {
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
    virtual ~InterpreterHandler() {
    }

    virtual std::string getOutputFilename(const std::string &filename) = 0;
    virtual llvm::raw_ostream *openOutputFile(const std::string &filename) = 0;
};

class Interpreter {
public:
    /// ModuleOptions - Module level options which can be set when
    /// registering a module with the interpreter.
    struct ModuleOptions {
        std::vector<std::string> ExtraLibraries;
        bool Optimize;
        bool Snapshot;
        llvm::legacy::FunctionPassManager *CustomPasses;

        ModuleOptions(const std::vector<std::string> &_ExtraLibraries, bool _Optimize, bool _CheckDivZero,
                      llvm::legacy::FunctionPassManager *_CustomPasses = NULL)
            : ExtraLibraries(_ExtraLibraries), Optimize(_Optimize), Snapshot(false), CustomPasses(_CustomPasses) {
        }
    };

protected:
    Interpreter() {
    }

public:
    virtual ~Interpreter() {
    }

    /// Register the module to be executed.
    ///
    /// \return The final module after it has been optimized, checks
    /// inserted, and modified for interpretation.
    virtual const llvm::Module *setModule(llvm::Module *module, const ModuleOptions &opts,
                                          bool createStatsTracker = true) = 0;
};

} // namespace klee

#endif
