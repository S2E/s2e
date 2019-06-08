///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <klee/Expr.h>
#include <llvm/Support/CommandLine.h>

#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>

#include <s2e/cpu.h>
#include <s2e/s2e_config.h>

namespace {
using namespace llvm;

cl::opt<bool> VerboseOnSymbolicAddress("verbose-on-symbolic-address", cl::desc("Print onSymbolicAddress details"),
                                       cl::init(false));
}

namespace s2e {

using namespace klee;

Executor::StatePair S2EExecutor::forkAndConcretize(S2EExecutionState *state, klee::ref<Expr> &value_) {
    assert(!state->m_runningConcrete);

    klee::ref<klee::Expr> value = value_;
    klee::ref<klee::ConstantExpr> concreteValue = state->toConstantSilent(value);

    klee::ref<klee::Expr> condition = EqExpr::create(concreteValue, value);
    StatePair sp = fork(*state, condition);

    // The condition is always true in the current state
    //(i.e., value == concreteValue holds).
    assert(sp.first == state);

    // It may happen that the simplifier figures out that
    // the condition is always true, in which case, no fork is needed.
    // TODO: find a test case for that
    if (sp.second) {
        // Re-execute the plugin invocation in the other state
        sp.second->pc = sp.second->prevPC;
    }

    notifyFork(*state, condition, sp);
    value_ = concreteValue;
    return sp;
}

void S2EExecutor::handleForkAndConcretize(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                          std::vector<klee::ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    S2EExecutionState *s2eState = dynamic_cast<S2EExecutionState *>(state);

    assert(args.size() == 4);
    klee::ref<klee::Expr> address = args[0];
    klee::ref<klee::Expr> isTargetPc = args[3];

    klee::ref<klee::ConstantExpr> concreteAddress = s2eState->toConstantSilent(address);

    if (isa<klee::ConstantExpr>(address)) {
        state->bindLocal(target, address);
        return;
    }

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
    StatePair sp = s2eExecutor->fork(*state, condition);

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

void S2EExecutor::handleMakeSymbolic(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                     std::vector<klee::ref<Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    s2eState->makeSymbolic(args);
}

void S2EExecutor::handleGetValue(klee::Executor *executor, klee::ExecutionState *state, klee::KInstruction *target,
                                 std::vector<klee::ref<klee::Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    assert(args.size() == 3 && "Expected three args to tcg_llvm_get_value: addr, size, add_constraint");

    // KLEE address of variable
    klee::ref<klee::ConstantExpr> kleeAddress = cast<klee::ConstantExpr>(args[0]);

    // Size in bytes
    uint64_t sizeInBytes = cast<klee::ConstantExpr>(args[1])->getZExtValue();

    // Add a constraint permanently?
    bool add_constraint = cast<klee::ConstantExpr>(args[2])->getZExtValue();

    // Read the value and concretize it.
    // The value will be stored at kleeAddress
    std::vector<klee::ref<Expr>> result;
    s2eState->kleeReadMemory(kleeAddress, sizeInBytes, nullptr, false, true, add_constraint);
}

void S2EExecutor::handlerWriteMemIoVaddr(klee::Executor *executor, klee::ExecutionState *state,
                                         klee::KInstruction *target, std::vector<klee::ref<klee::Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    assert(args.size() == 2);

    klee::ConstantExpr *reset = dyn_cast<klee::ConstantExpr>(args[1]);
    assert(reset && "Invalid parameter");

    if (reset->getZExtValue()) {
        s2eState->m_memIoVaddr = nullptr;
    } else {
        s2eState->m_memIoVaddr = args[0];
    }
}

void S2EExecutor::handlerBeforeMemoryAccess(klee::Executor *executor, klee::ExecutionState *state,
                                            klee::KInstruction *target, std::vector<klee::ref<klee::Expr>> &args) {
    assert(dynamic_cast<S2EExecutor *>(executor));
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);

    if (s2eExecutor->m_s2e->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.empty()) {
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

    s2eExecutor->m_s2e->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.emit(s2eState, vaddr, value, flags);
}

void S2EExecutor::handlerAfterMemoryAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                           std::vector<klee::ref<klee::Expr>> &args) {
    assert(dynamic_cast<S2EExecutor *>(executor));

    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    if (s2eExecutor->m_s2e->getCorePlugin()->onAfterSymbolicDataMemoryAccess.empty()) {
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
        s2eExecutor->m_s2e->getCorePlugin()->onConcreteDataMemoryAccess.emit(
            s2eState, cast<klee::ConstantExpr>(vaddr)->getZExtValue(), cast<klee::ConstantExpr>(value)->getZExtValue(),
            klee::Expr::getMinBytesForWidth(width), flags);
    } else {
        s2eExecutor->m_s2e->getCorePlugin()->onAfterSymbolicDataMemoryAccess.emit(s2eState, vaddr, haddr, value, flags);
    }
}

void S2EExecutor::handlerTraceInstruction(klee::Executor *executor, klee::ExecutionState *state,
                                          klee::KInstruction *target, std::vector<klee::ref<klee::Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    g_s2e->getDebugStream() << "pc=" << hexval(s2eState->regs()->getPc())
                            << " EAX: " << s2eState->regs()->read(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32)
                            << " ECX: " << s2eState->regs()->read(offsetof(CPUX86State, regs[R_ECX]), klee::Expr::Int32)
                            << " CCSRC: " << s2eState->regs()->read(offsetof(CPUX86State, cc_src), klee::Expr::Int32)
                            << " CCDST: " << s2eState->regs()->read(offsetof(CPUX86State, cc_dst), klee::Expr::Int32)
                            << " CCTMP: " << s2eState->regs()->read(offsetof(CPUX86State, cc_tmp), klee::Expr::Int32)
                            << " CCOP: " << s2eState->regs()->read(offsetof(CPUX86State, cc_op), klee::Expr::Int32)
                            << '\n';
}

void S2EExecutor::handlerOnTlbMiss(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                   std::vector<klee::ref<klee::Expr>> &args) {
    assert(dynamic_cast<S2EExecutor *>(executor));

    assert(args.size() == 2);

    klee::ref<Expr> addr = args[0];
    bool isWrite = cast<klee::ConstantExpr>(args[1])->getZExtValue();

    if (!isa<klee::ConstantExpr>(addr)) {
        /*
        g_s2e->getWarningsStream()
                << "Warning: s2e_on_tlb_miss does not support symbolic addresses"
                << '\n';
                */
        return;
    }

    uint64_t constAddress;
    constAddress = cast<klee::ConstantExpr>(addr)->getZExtValue(64);

    s2e_on_tlb_miss(constAddress, isWrite, nullptr);
}

void S2EExecutor::handlerTraceMmioAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                         std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 4);

    uint64_t physAddress = state->toConstant(args[0], "MMIO address")->getZExtValue();
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

void S2EExecutor::handlerTracePortAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                         std::vector<klee::ref<klee::Expr>> &args) {
    assert(dynamic_cast<S2EExecutor *>(executor));

    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);

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

    if (!s2eExecutor->m_s2e->getCorePlugin()->onPortAccess.empty()) {
        s2eExecutor->m_s2e->getCorePlugin()->onPortAccess.emit(s2eState, port, resizedValue, isWrite);
    }
}
}
