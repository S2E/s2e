//===-- SpecialFunctionHandler.h --------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_SPECIALFUNCTIONHANDLER_H
#define KLEE_SPECIALFUNCTIONHANDLER_H

#include <map>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace klee {
class Executor;
class Expr;
class ExecutionState;
struct KInstruction;
template <typename T> class ref;

class SpecialFunctionHandler {
public:
    typedef void (SpecialFunctionHandler::*Handler)(ExecutionState &state, KInstruction *target,
                                                    std::vector<ref<Expr>> &arguments);

    typedef void (*FunctionHandler)(Executor *executor, ExecutionState *state, KInstruction *target,
                                    std::vector<ref<Expr>> &arguments);

    typedef std::map<const llvm::Function *, std::pair<Handler, bool>> handlers_ty;

    typedef std::map<const llvm::Function *, std::pair<FunctionHandler, bool>> uhandlers_ty;

    handlers_ty handlers;

    /* uhandlers are user defined handlers that can be added
       or removed during symbolic execution. */
    uhandlers_ty uhandlers;

    class Executor &executor;

public:
    SpecialFunctionHandler(Executor &_executor);

    /// Perform any modifications on the LLVM module before it is
    /// prepared for execution. At the moment this involves deleting
    /// unused function bodies and marking intrinsics with appropriate
    /// flags for use in optimizations.
    void prepare(const llvm::Module &mod);

    /// Initialize the internal handler map after the module has been
    /// prepared for execution.
    void bind(const llvm::Module &mod);

    /// Add user handler function
    void addUHandler(llvm::Function *f, FunctionHandler handler);

    bool handle(ExecutionState &state, llvm::Function *f, KInstruction *target, std::vector<ref<Expr>> &arguments);
};
} // namespace klee

#endif
