///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <klee/Expr.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>

#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>

#include <s2e/cpu.h>
#include <s2e/s2e_config.h>

#include <s2e/FunctionHandlers.h>

namespace {
using namespace llvm;

cl::opt<bool> VerboseOnSymbolicAddress("verbose-on-symbolic-address", cl::desc("Print onSymbolicAddress details"),
                                       cl::init(false));
} // namespace

namespace s2e {

using namespace klee;

void handleForkAndConcretize(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                             std::vector<klee::ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    S2EExecutionState *s2eState = dynamic_cast<S2EExecutionState *>(state);

    assert(args.size() == 4);
    klee::ref<klee::Expr> address = args[0];
    klee::ref<klee::Expr> isTargetPc = args[3];

    // If address is already concrete, nothing to fork
    if (dyn_cast<klee::ConstantExpr>(address)) {
        state->bindLocal(target, address);
        return;
    }

    auto concreteAddress = state->toConstantSilent(address);

    bool doConcretize = false;

    CorePlugin::symbolicAddressReason reason;
    if (isTargetPc->isZero())
        reason = CorePlugin::symbolicAddressReason::MEMORY;
    else
        reason = CorePlugin::symbolicAddressReason::PC;

    if (VerboseOnSymbolicAddress) {
        g_s2e->getDebugStream(s2eState) << "onSymbolicAddress at " << hexval(s2eState->regs()->getPc()) << " (reason "
                                        << dyn_cast<klee::ConstantExpr>(isTargetPc)->getZExtValue()
                                        << "): " << hexval(concreteAddress->getZExtValue()) << " " << address << "\n";
    }

    unsigned ptrSize = s2eState->getPointerSize();
    klee::ref<klee::Expr> castedAddress = address;
    if (ptrSize == sizeof(uint32_t)) {
        castedAddress = klee::ExtractExpr::create(address, 0, klee::Expr::Int32);
    }

    g_s2e->getCorePlugin()->onSymbolicAddress.emit(s2eState, castedAddress, concreteAddress->getZExtValue(),
                                                   doConcretize, reason);

    klee::ref<klee::Expr> condition = EqExpr::create(concreteAddress, address);

    if (doConcretize) {
        if (!state->addConstraint(condition)) {
            abort();
        }
        state->bindLocal(target, concreteAddress);
        return;
    }

    // XXX: may create deep paths!
    Executor::StatePair sp = s2eExecutor->fork(*state, condition);

    // The condition is always true in the current state
    //(i.e., expr == concreteAddress holds).
    assert(sp.first == state);

    // It may happen that the simplifier figures out that
    // the condition is always true, in which case, no fork is needed.
    // TODO: find a test case for that
    if (sp.second) {
        // Will have to reexecute handleForkAndConcretize in the speculative state
        sp.second->pc = sp.second->prevPC;
    }

    state->bindLocal(target, concreteAddress);

    s2eExecutor->notifyFork(*state, condition, sp);
}
#if defined(TARGET_I386) || defined(TARGET_X86_64)
static void handleGetValue(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                           std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 2 && "Expected three args to tcg_llvm_get_value: value, add_constraint");

    // KLEE address of variable
    auto value = args[0];

    // Add a constraint permanently?
    bool addConstraint = cast<klee::ConstantExpr>(args[1])->getZExtValue();

    klee::ref<Expr> result;

    if (addConstraint) {
        result = state->toConstant(value, "called tcg_llvm_get_value");
    } else {
        result = state->toConstantSilent(value);
    }

    state->bindLocal(target, result);
}
#endif

static void handlerWriteMemIoVaddr(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                                   std::vector<klee::ref<klee::Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    assert(args.size() == 2);

    klee::ConstantExpr *reset = dyn_cast<klee::ConstantExpr>(args[1]);
    assert(reset && "Invalid parameter");

    if (reset->getZExtValue()) {
        s2eState->setMemIoVaddr(nullptr);
    } else {
        s2eState->setMemIoVaddr(args[0]);
    }
}

static void handlerBeforeMemoryAccess(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                                      std::vector<klee::ref<klee::Expr>> &args) {
    if (g_s2e->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.empty()) {
        return;
    }

    assert(args.size() == 4);

    // 1st arg: virtual address
    klee::ref<Expr> vaddr = args[0];
    if (isa<klee::ConstantExpr>(vaddr)) {
        return;
    }

    // 3rd arg: width
    Expr::Width width = cast<klee::ConstantExpr>(args[2])->getZExtValue() * 8;
    assert(width <= 64);

    // 2nd arg: value
    klee::ref<Expr> value;
    if (args[1]->getWidth() > width) {
        value = klee::ExtractExpr::create(args[1], 0, width);
    } else {
        value = args[1];
    }

    // 4th arg: flags
    unsigned flags = cast<klee::ConstantExpr>(args[3])->getZExtValue();

    assert(dynamic_cast<S2EExecutionState *>(state));
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);

    g_s2e->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.emit(s2eState, vaddr, value, flags);
}

void handlerAfterMemoryAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<klee::ref<klee::Expr>> &args) {
    auto corePlugin = g_s2e->getCorePlugin();

    if (corePlugin->onAfterSymbolicDataMemoryAccess.empty() && corePlugin->onConcreteDataMemoryAccess.empty()) {
        return;
    }

    assert(dynamic_cast<S2EExecutionState *>(state));
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);

    assert(args.size() == 5);
    // 1st arg: virtual address
    klee::ref<Expr> vaddr = args[0];

    // 3rd arg: width
    Expr::Width width = cast<klee::ConstantExpr>(args[2])->getZExtValue() * 8;
    assert(width <= 64);

    // 2nd arg: value
    klee::ref<Expr> value;
    if (args[1]->getWidth() > width) {
        value = klee::ExtractExpr::create(args[1], 0, width);
    } else {
        value = args[1];
    }

    // 4th arg: flags
    unsigned flags = cast<klee::ConstantExpr>(args[3])->getZExtValue();

    // 5th arg: pc (which we ignore here)

    klee::ref<Expr> haddr = klee::ConstantExpr::create(0, klee::Expr::Int64);

    if (isa<klee::ConstantExpr>(value) && isa<klee::ConstantExpr>(vaddr)) {
        g_s2e->getCorePlugin()->onConcreteDataMemoryAccess.emit(
            s2eState, cast<klee::ConstantExpr>(vaddr)->getZExtValue(), cast<klee::ConstantExpr>(value)->getZExtValue(),
            klee::Expr::getMinBytesForWidth(width), flags);
    } else {
        g_s2e->getCorePlugin()->onAfterSymbolicDataMemoryAccess.emit(s2eState, vaddr, haddr, value, flags);
    }
}

// TODO: implement s2e_on_tlb_miss in symbolic mode
#if 0
static void handlerOnTlbMiss(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                   std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 2);

    klee::ref<Expr> addr = args[0];
    bool isWrite = cast<klee::ConstantExpr>(args[1])->getZExtValue();

    if (!isa<klee::ConstantExpr>(addr)) {
        return;
    }

    uint64_t constAddress;
    constAddress = cast<klee::ConstantExpr>(addr)->getZExtValue(64);

    s2e_on_tlb_miss(constAddress, isWrite, nullptr);
}
#endif

static void handlerTraceMmioAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                   std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 4);

    auto symbolicPhysAddress = args[0];
    if (!g_symbolicMemoryHook.hasHook()) {
        // Avoid forced concretizations if symbolic hardware is not enabled
        state->bindLocal(target, symbolicPhysAddress);
        return;
    }

    uint64_t physAddress = state->toConstant(symbolicPhysAddress, "MMIO address")->getZExtValue();
    klee::ref<Expr> value = args[1];
    unsigned size = cast<klee::ConstantExpr>(args[2])->getZExtValue();

    if (!g_symbolicMemoryHook.symbolic(nullptr, physAddress, size)) {
        state->bindLocal(target, value);
        return;
    }

    klee::ref<Expr> resizedValue = klee::ExtractExpr::create(value, 0, size * 8);
    bool isWrite = cast<klee::ConstantExpr>(args[3])->getZExtValue();

    if (isWrite) {
        g_symbolicMemoryHook.write(nullptr, physAddress, resizedValue, SYMB_MMIO);
        state->bindLocal(target, value);
    } else {
        klee::ref<Expr> ret = g_symbolicMemoryHook.read(nullptr, physAddress, resizedValue, SYMB_MMIO);
        assert(ret->getWidth() == resizedValue->getWidth());
        ret = klee::ZExtExpr::create(ret, klee::Expr::Int64);
        state->bindLocal(target, ret);
    }
}
#if defined(TARGET_I386) || defined(TARGET_X86_64)
static void handlerTracePortAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                   std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 4);
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);

    klee::ref<klee::ConstantExpr> port = state->toConstant(args[0], "Symbolic I/O port");
    klee::ref<Expr> inputValue = args[1];
    klee::Expr::Width width = cast<klee::ConstantExpr>(args[2])->getZExtValue();
    klee::ref<Expr> resizedValue = klee::ExtractExpr::create(inputValue, 0, width);
    bool isWrite = cast<klee::ConstantExpr>(args[3])->getZExtValue();
    int isSymb = g_symbolicPortHook.symbolic(port->getZExtValue());

    if (isWrite) {
        bool callOrig = true;
        if (isSymb) {
            callOrig = g_symbolicPortHook.write(port->getZExtValue(), resizedValue);
        }

        if (callOrig) {
            state->toConstant(resizedValue, "Symbolic I/O port value");
        }

        state->bindLocal(target, klee::ConstantExpr::create(callOrig, klee::Expr::Int64));

    } else {
        /**
         * If we have a symbolic read, augment with a symbolic value the concrete value returned by
         * libcpus's native port handlers. This way, we can have concolic execution.
         */
        klee::ref<klee::ConstantExpr> concreteInputValue = cast<klee::ConstantExpr>(resizedValue);
        klee::ref<Expr> outputValue = concreteInputValue;
        if (isSymb) {
            outputValue = g_symbolicPortHook.read(port->getZExtValue(), width / 8, concreteInputValue->getZExtValue());
        }

        state->bindLocal(target, klee::ZExtExpr::create(outputValue, klee::Expr::Int64));
    }

    if (!g_s2e->getCorePlugin()->onPortAccess.empty()) {
        g_s2e->getCorePlugin()->onPortAccess.emit(s2eState, port, resizedValue, isWrite);
    }
}
#endif

static Handler s_handlers[] = {{"tcg_llvm_write_mem_io_vaddr", handlerWriteMemIoVaddr, nullptr},
                               {"tcg_llvm_before_memory_access", handlerBeforeMemoryAccess, nullptr},
                               {"tcg_llvm_after_memory_access", handlerAfterMemoryAccess, nullptr},
                               {"tcg_llvm_trace_mmio_access", handlerTraceMmioAccess, nullptr},
                               {"tcg_llvm_fork_and_concretize", handleForkAndConcretize, nullptr},
#if defined(TARGET_I386) || defined(TARGET_X86_64)
                               {"tcg_llvm_trace_port_access", handlerTracePortAccess, nullptr},
                               {"tcg_llvm_get_value", handleGetValue, nullptr},
#endif
                               {"", nullptr, nullptr}};

void S2EExecutor::registerFunctionHandlers(llvm::Module &module) {
    for (unsigned i = 0; s_handlers[i].handler; ++i) {
        const auto &hdlr = s_handlers[i];
        auto function = module.getFunction(hdlr.name);
        if (!function) {
            if (hdlr.getOrInsertFunction) {
                auto ty = hdlr.getOrInsertFunction(module);
                auto fc = module.getOrInsertFunction(hdlr.name, ty);
                function = dyn_cast<Function>(fc.getCallee());
                if (!function) {
                    abort();
                }
            } else {
                abort();
            }
        }

        addSpecialFunctionHandler(function, hdlr.handler);
    }
}
} // namespace s2e
