//===-- SpecialFunctionHandler.cpp ----------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/Memory.h"
#include "klee/TimingSolver.h"
#include "SpecialFunctionHandler.h"

#include "klee/ExecutionState.h"

#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"

#include "klee/Executor.h"

#include "llvm/ADT/Twine.h"
#include "llvm/IR/Module.h"

#include <errno.h>

using namespace llvm;
using namespace klee;

struct HandlerInfo {
    const char *name;
    SpecialFunctionHandler::Handler handler;
    bool doesNotReturn;  /// Intrinsic terminates the process
    bool hasReturnValue; /// Intrinsic has a return value
    bool doNotOverride;  /// Intrinsic should not be used if already defined
};

HandlerInfo handlerInfo[] = {
#define add(name, handler, ret) \
    { name, &SpecialFunctionHandler::handler, false, ret, false }
#define addDNR(name, handler) \
    { name, &SpecialFunctionHandler::handler, true, false, false }
#undef addDNR
#undef add
};

SpecialFunctionHandler::SpecialFunctionHandler(Executor &_executor) : executor(_executor) {
}

void SpecialFunctionHandler::prepare(const llvm::Module &mod) {
    unsigned N = sizeof(handlerInfo) / sizeof(handlerInfo[0]);

    for (unsigned i = 0; i < N; ++i) {
        HandlerInfo &hi = handlerInfo[i];
        auto f = mod.getFunction(hi.name);

        // No need to create if the function doesn't exist, since it cannot
        // be called in that case.

        if (f && (!hi.doNotOverride || f->isDeclaration())) {
            // Make sure NoReturn attribute is set, for optimization and
            // coverage counting.
            if (hi.doesNotReturn) {
                f->addFnAttr(Attribute::NoReturn);
            }

            // Change to a declaration since we handle internally (simplifies
            // module and allows deleting dead code).
            if (!f->isDeclaration()) {
                f->deleteBody();
            }
        }
    }
}

void SpecialFunctionHandler::bind(const llvm::Module &mod) {
    unsigned N = sizeof(handlerInfo) / sizeof(handlerInfo[0]);

    for (unsigned i = 0; i < N; ++i) {
        HandlerInfo &hi = handlerInfo[i];
        auto f = mod.getFunction(hi.name);

        if (f && (!hi.doNotOverride || f->isDeclaration()))
            handlers[f] = std::make_pair(hi.handler, hi.hasReturnValue);
    }
}

void SpecialFunctionHandler::addUHandler(llvm::Function *f, FunctionHandler h) {
    uhandlers[f] = std::make_pair(h, f->getReturnType()->getTypeID() != llvm::Type::VoidTyID);
}

bool SpecialFunctionHandler::handle(ExecutionState &state, Function *f, KInstruction *target,
                                    std::vector<ref<Expr>> &arguments) {
    handlers_ty::iterator it = handlers.find(f);
    if (it != handlers.end()) {
        Handler h = it->second.first;
        bool hasReturnValue = it->second.second;
        // FIXME: Check this... add test?
        if (!hasReturnValue && !target->inst->use_empty()) {
            executor.terminateState(state, "expected return value from void special function");
        } else {
            (this->*h)(state, target, arguments);
        }
        return true;
    }

    uhandlers_ty::iterator uit = uhandlers.find(f);
    if (uit != uhandlers.end()) {
        FunctionHandler h = uit->second.first;
        bool hasReturnValue = uit->second.second;
        // FIXME: Check this... add test?
        if (!hasReturnValue && !target->inst->use_empty()) {
            executor.terminateState(state, "expected return value from void special function");
        } else {
            h(&executor, &state, target, arguments);
        }
        return true;
    }

    return false;
}
