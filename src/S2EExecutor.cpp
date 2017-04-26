///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __APPLE__
#include <malloc.h>
#endif

#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/s2e_config.h>

#include <s2e/S2EDeviceState.h>
#include <s2e/S2EStatsTracker.h>

#include <s2e/s2e_libcpu.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Process.h>

#include <llvm/Config/config.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <llvm/ADT/IntervalMap.h>

#include <klee/CoreStats.h>
#include <klee/ExternalDispatcher.h>
#include <klee/Memory.h>
#include <klee/PTree.h>
#include <klee/Searcher.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <klee/TimerStatIncrementer.h>
#include <klee/UserSearcher.h>
#include <klee/util/ExprTemplates.h>

#include <llvm/Support/TimeValue.h>

#include <glib.h>
#include <sstream>
#include <vector>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <tr1/functional>

//#define S2E_DEBUG_MEMORY
//#define S2E_DEBUG_INSTRUCTIONS
//#define S2E_DEBUG_MEMOBJECT_NAME
//#define S2E_TRACE_EFLAGS
//#define FORCE_CONCRETIZATION

using namespace std;
using namespace llvm;
using namespace klee;

// clang-format off
namespace {
    // This should be true by default, because otherwise overheads are way too high.
    // Drawback is that execution is not fully consistent by default.
    cl::opt<bool>
    StateSharedMemory("state-shared-memory",
            cl::desc("Allow unimportant memory regions (like video RAM) to be shared between states"),
            cl::init(true));


    cl::opt<bool>
    FlushTBsOnStateSwitch("flush-tbs-on-state-switch",
            cl::desc("Flush translation blocks when switching states -"
                     " disabling leads to faster but possibly incorrect execution"),
            cl::init(true));

    cl::opt<bool>
    KeepLLVMFunctions("keep-llvm-functions",
            cl::desc("Never delete generated LLVM functions"),
            cl::init(false));

    //The default is true for two reasons:
    //1. Symbolic addresses are very expensive to handle
    //2. There is lazy forking which will eventually enumerate
    //all possible addresses.
    //Overall, we have more path explosion, but at least execution
    //does not get stuck in various places.
    cl::opt<bool>
    ForkOnSymbolicAddress("fork-on-symbolic-address",
            cl::desc("Fork on each memory access with symbolic address"),
            cl::init(true));

    cl::opt<bool>
    ConcretizeIoAddress("concretize-io-address",
            cl::desc("Concretize symbolic I/O addresses"),
            cl::init(true));

    //XXX: Works for MMIO only, add support for port I/O
    cl::opt<bool>
    ConcretizeIoWrites("concretize-io-writes",
            cl::desc("Concretize symbolic I/O writes"),
            cl::init(true));

    cl::opt<bool>
    PrintLLVMInstructions("print-llvm-instructions",
            cl::desc("Traces all LLVM instructions sent to KLEE"),
            cl::init(false));

    cl::opt<bool>
    EnableForking("enable-forking",
            cl::desc("Enable forking of S2E states"),
            cl::init(true));

    cl::opt<bool>
    VerboseFork("verbose-fork-info",
            cl::desc("Print detailed information on forks"),
            cl::init(false));

    cl::opt<bool>
    VerboseStateSwitching("verbose-state-switching",
            cl::desc("Print detailed information on state switches"),
            cl::init(false));

    cl::opt<bool>
    VerboseTbFinalize("verbose-tb-finalize",
            cl::desc("Print detailed information when finalizing a partially-completed TB"),
            cl::init(false));

    cl::opt<bool>
    UseFastHelpers("use-fast-helpers",
            cl::desc("Replaces LLVM bitcode with fast symbolic-aware equivalent native helpers"),
            cl::init(false));

    cl::opt<unsigned>
    ClockSlowDown("clock-slow-down",
            cl::desc("Slow down factor when interpreting LLVM code"),
            cl::init(101));

    cl::opt<unsigned>
    ClockSlowDownFastHelpers("clock-slow-down-fast-helpers",
            cl::desc("Slow down factor when interpreting LLVM code and using fast helpers"),
            cl::init(11));

    cl::opt<bool>
    EnableTimingLog("enable-executor-timing",
            cl::desc("Measures execution times of various parts of S2E"),
            cl::init(false));

    cl::opt<bool>
    SinglePathMode("single-path-mode",
            cl::desc("Faster TLB, but forces single path execution"),
            cl::init(false));

    cl::opt<bool>
    VerboseOnSymbolicAddress("verbose-on-symbolic-address",
            cl::desc("Print onSymbolicAddress details"),
            cl::init(false));
}

//The logs may be flooded with messages when switching execution mode.
//This option allows disabling printing mode switches.
cl::opt<bool>
PrintModeSwitch("print-mode-switch",
            cl::desc("Print message when switching from symbolic to concrete and vice versa"),
            cl::init(false));

cl::opt<bool>
PrintForkingStatus("print-forking-status",
            cl::desc("Print message when enabling/disabling forking."),
            cl::init(false));

cl::opt<bool>
VerboseStateDeletion("verbose-state-deletion",
            cl::desc("Print detailed information on state deletion"),
            cl::init(false));

//Concolic mode is the default because it works better than symbex.
cl::opt<bool>
ConcolicMode("use-concolic-execution",
            cl::desc("Concolic execution mode"),
            cl::init(true));

cl::opt<bool>
DebugConstraints("debug-constraints",
            cl::desc("Check that added constraints are satisfiable"),
            cl::init(false));

cl::opt<std::string>
PersistentTbCache("persistent-tb-cache",
            cl::desc("Path to the persistent TB cache .bc file"),
            cl::init(""));

extern cl::opt<bool> UseExprSimplifier;

extern "C" {
    int g_s2e_fork_on_symbolic_address = 0;
    int g_s2e_concretize_io_addresses = 1;
    int g_s2e_concretize_io_writes = 1;

    // XXX: the following should be thread-local when
    // we implement support for multi-cores in the guest

    // Tells the main loop whether it is ok to call
    // the native call directly, without going through
    // several layers of indirection in S2EExecutor.
    // This variable is set when all registers are concrete
    // and symbolic execution is not forced for the current tb.
    int g_s2e_fast_concrete_invocation = 0;

    // Direct access to the execution function.
    // Avoids going through a wrapper.
    se_libcpu_tb_exec_t se_libcpu_tb_exec = &s2e::S2EExecutor::executeTranslationBlockFast;

    char *g_s2e_running_concrete = NULL;

    char *g_s2e_running_exception_emulation_code = NULL;

    se_do_interrupt_all_t g_s2e_do_interrupt_all = &s2e::S2EExecutor::doInterruptAll;

    //Shortcut to speed up access to the dirty mask (it is always concrete)
    uintptr_t g_se_dirty_mask_addend = 0;

    void s2e_print_instructions(int v);
    void s2e_print_instructions(int v) {
        PrintLLVMInstructions = v;
    }

    int g_s2e_single_path_mode = 0;
}
// clang-format on

namespace s2e {

/* Global array to hold tb function arguments */
volatile void *tb_function_args[3];

/* External dispatcher to convert longjmp's into C++ exceptions */
class S2EExternalDispatcher : public klee::ExternalDispatcher {
protected:
    virtual bool runProtectedCall(llvm::Function *f, uint64_t *args);

public:
    S2EExternalDispatcher(llvm::LLVMContext &context) : ExternalDispatcher(context) {
    }

    void removeFunction(llvm::Function *f);
};

extern "C" {

// FIXME: This is not reentrant.
static jmp_buf s2e_escapeCallJmpBuf;
static jmp_buf s2e_cpuExitJmpBuf;

#ifdef _WIN32
static void s2e_ext_sigsegv_handler(int signal) {
}
#else
static void s2e_ext_sigsegv_handler(int signal, siginfo_t *info, void *context) {
    longjmp(s2e_escapeCallJmpBuf, 1);
}
#endif
}

bool S2EExternalDispatcher::runProtectedCall(Function *f, uint64_t *args) {
#ifndef _WIN32
    struct sigaction segvAction, segvActionOld;
#endif
    bool res;

    if (!f)
        return false;

    gTheArgsP = args;

#ifdef _WIN32
    signal(SIGSEGV, s2e_ext_sigsegv_handler);
#else
    segvAction.sa_handler = 0;
    memset(&segvAction.sa_mask, 0, sizeof(segvAction.sa_mask));
    segvAction.sa_flags = SA_SIGINFO;
    segvAction.sa_sigaction = s2e_ext_sigsegv_handler;
    sigaction(SIGSEGV, &segvAction, &segvActionOld);
#endif

    memcpy(s2e_cpuExitJmpBuf, env->jmp_env, sizeof(env->jmp_env));

    if (setjmp(env->jmp_env)) {
        memcpy(env->jmp_env, s2e_cpuExitJmpBuf, sizeof(env->jmp_env));
        throw CpuExitException();
    } else {
        if (setjmp(s2e_escapeCallJmpBuf)) {
            res = false;
        } else {
            std::vector<GenericValue> gvArgs;
            ExecutionEngine *ee = getExecutionEngine(f);

            ee->runFunction(f, gvArgs);
            res = true;
        }
    }

    memcpy(env->jmp_env, s2e_cpuExitJmpBuf, sizeof(env->jmp_env));

#ifdef _WIN32
#warning Implement more robust signal handling on windows
    signal(SIGSEGV, SIG_IGN);
#else
    sigaction(SIGSEGV, &segvActionOld, 0);
#endif
    return res;
}

/**
 * Remove all mappings between calls to external functions
 * and the actual external call stub generated by KLEE.
 * Also remove the machine code for the stub and the stub itself.
 * This is used whenever S2E deletes a translation block and its LLVM
 * representation. Failing to do so would leave stale references to
 * machine code in KLEE's external dispatcher.
 */
void S2EExternalDispatcher::removeFunction(llvm::Function *f) {
    dispatchers_ty::iterator it, itn;

    it = dispatchers.begin();
    while (it != dispatchers.end()) {
        if ((*it).first->getParent()->getParent() == f) {

            llvm::Function *dispatcher = (*it).second;
            dispatcher->eraseFromParent();

            itn = it;
            ++itn;
            dispatchers.erase(it);
            it = itn;
        } else {
            ++it;
        }
    }
}

S2EHandler::S2EHandler(S2E *s2e) : m_s2e(s2e) {
}

llvm::raw_ostream &S2EHandler::getInfoStream() const {
    return m_s2e->getInfoStream();
}

std::string S2EHandler::getOutputFilename(const std::string &fileName) {
    return m_s2e->getOutputFilename(fileName);
}

llvm::raw_ostream *S2EHandler::openOutputFile(const std::string &fileName) {
    return m_s2e->openOutputFile(fileName);
}

/* klee-related function */
void S2EHandler::incPathsExplored() {
    m_pathsExplored++;
}

/* klee-related function */
void S2EHandler::processTestCase(const klee::ExecutionState &state, const char *err, const char *suffix) {
    // XXX: This stuff is not used anymore
    // Use onTestCaseGeneration event instead.
}

void S2EExecutor::handlerWriteMemIoVaddr(klee::Executor *executor, klee::ExecutionState *state,
                                         klee::KInstruction *target, std::vector<klee::ref<klee::Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    assert(args.size() == 2);

    klee::ConstantExpr *reset = dyn_cast<klee::ConstantExpr>(args[1]);
    assert(reset && "Invalid parameter");

    if (reset->getZExtValue()) {
        s2eState->m_memIoVaddr = NULL;
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
    g_s2e->getDebugStream() << "pc=" << hexval(s2eState->getPc()) << " EAX: "
                            << s2eState->readCpuRegister(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32)
                            << " ECX: "
                            << s2eState->readCpuRegister(offsetof(CPUX86State, regs[R_ECX]), klee::Expr::Int32)
                            << " CCSRC: " << s2eState->readCpuRegister(offsetof(CPUX86State, cc_src), klee::Expr::Int32)
                            << " CCDST: " << s2eState->readCpuRegister(offsetof(CPUX86State, cc_dst), klee::Expr::Int32)
                            << " CCTMP: " << s2eState->readCpuRegister(offsetof(CPUX86State, cc_tmp), klee::Expr::Int32)
                            << " CCOP: " << s2eState->readCpuRegister(offsetof(CPUX86State, cc_op), klee::Expr::Int32)
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

    s2e_on_tlb_miss(constAddress, isWrite, NULL);
}

void S2EExecutor::handlerTraceMmioAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                         std::vector<klee::ref<klee::Expr>> &args) {
    assert(args.size() == 4);
    S2EExecutor *e = static_cast<S2EExecutor *>(executor);

    uint64_t physAddress = e->toConstant(*state, args[0], "MMIO address")->getZExtValue();
    klee::ref<Expr> value = args[1];
    unsigned size = cast<klee::ConstantExpr>(args[2])->getZExtValue();

    if (!g_symbolicMemoryHook.symbolic(NULL, physAddress, size)) {
        e->bindLocal(target, *state, value);
        return;
    }

    klee::ref<Expr> resizedValue = klee::ExtractExpr::create(value, 0, size * 8);
    bool isWrite = cast<klee::ConstantExpr>(args[3])->getZExtValue();

    if (isWrite) {
        g_symbolicMemoryHook.write(NULL, physAddress, resizedValue, SYMB_MMIO);
        e->bindLocal(target, *state, value);
    } else {
        klee::ref<Expr> ret = g_symbolicMemoryHook.read(NULL, physAddress, resizedValue, SYMB_MMIO);
        assert(ret->getWidth() == resizedValue->getWidth());
        ret = klee::ZExtExpr::create(ret, klee::Expr::Int64);
        e->bindLocal(target, *state, ret);
    }
}

void S2EExecutor::handlerTracePortAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                         std::vector<klee::ref<klee::Expr>> &args) {
    assert(dynamic_cast<S2EExecutor *>(executor));

    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);

    assert(args.size() == 4);
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);

    klee::ref<klee::ConstantExpr> port = s2eExecutor->toConstant(*state, args[0], "Symbolic I/O port");
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
            s2eExecutor->toConstant(*state, resizedValue, "Symbolic I/O port value");
        }

        s2eExecutor->bindLocal(target, *state, klee::ConstantExpr::create(callOrig, klee::Expr::Int64));

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

        s2eExecutor->bindLocal(target, *state, klee::ZExtExpr::create(outputValue, klee::Expr::Int64));
    }

    if (!s2eExecutor->m_s2e->getCorePlugin()->onPortAccess.empty()) {
        s2eExecutor->m_s2e->getCorePlugin()->onPortAccess.emit(s2eState, port, resizedValue, isWrite);
    }
}

klee::ref<klee::ConstantExpr> S2EExecutor::simplifyAndGetExample(S2EExecutionState *state, klee::ref<Expr> &value) {
    value = state->constraints.simplifyExpr(value);

    if (UseExprSimplifier) {
        value = simplifyExpr(*state, value);
    }

    if (isa<klee::ConstantExpr>(value)) {
        return dyn_cast<klee::ConstantExpr>(value);
    }

    klee::ref<klee::ConstantExpr> concreteValue;

    if (ConcolicMode) {
        klee::ref<Expr> ca = state->concolics->evaluate(value);
        assert(dyn_cast<klee::ConstantExpr>(ca) && "Could not evaluate address");
        concreteValue = dyn_cast<klee::ConstantExpr>(ca);
    } else {
        // Not in concolic mode, will have to invoke the constraint solver
        // to compute a concrete value
        bool success = getSolver(*state)->getValue(Query(state->constraints, value), concreteValue);

        if (!success) {
            terminateStateEarly(*state, "Could not compute a concrete value for a symbolic address");
            assert(false && "Can't get here");
        }
    }

    return concreteValue;
}

Executor::StatePair S2EExecutor::forkAndConcretize(S2EExecutionState *state, klee::ref<Expr> &value_) {
    assert(!state->m_runningConcrete);

    klee::ref<klee::Expr> value = value_;
    klee::ref<klee::ConstantExpr> concreteValue = simplifyAndGetExample(state, value);

    klee::ref<klee::Expr> condition = EqExpr::create(concreteValue, value);
    StatePair sp = fork(*state, condition, true, true);

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

    klee::ref<klee::ConstantExpr> concreteAddress = s2eExecutor->simplifyAndGetExample(s2eState, address);

    if (isa<klee::ConstantExpr>(address)) {
        s2eExecutor->bindLocal(target, *state, address);
        return;
    }

    bool doConcretize = false;

    CorePlugin::symbolicAddressReason reason;
    if (isTargetPc->isZero())
        reason = CorePlugin::symbolicAddressReason::MEMORY;
    else
        reason = CorePlugin::symbolicAddressReason::PC;

    if (VerboseOnSymbolicAddress) {
        g_s2e->getDebugStream(s2eState) << "onSymbolicAddress at " << hexval(s2eState->getPc()) << " (reason "
                                        << dyn_cast<klee::ConstantExpr>(isTargetPc)->getZExtValue()
                                        << "): " << hexval(concreteAddress->getZExtValue()) << " " << address << "\n";
    }

    g_s2e->getCorePlugin()->onSymbolicAddress.emit(s2eState, address, concreteAddress->getZExtValue(), doConcretize,
                                                   reason);

    klee::ref<klee::Expr> condition = EqExpr::create(concreteAddress, address);

    if (doConcretize) {
        s2eExecutor->addConstraint(*state, condition);
        s2eExecutor->bindLocal(target, *state, concreteAddress);
        return;
    }

    // XXX: may create deep paths!
    StatePair sp = s2eExecutor->fork(*state, condition, true, true);

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

    s2eExecutor->bindLocal(target, *state, concreteAddress);

    s2eExecutor->notifyFork(*state, condition, sp);
}

void S2EExecutor::handleMakeSymbolic(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                     std::vector<klee::ref<Expr>> &args) {
    S2EExecutionState *s2eState = static_cast<S2EExecutionState *>(state);
    s2eState->makeSymbolic(args, false);
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
    s2eState->kleeReadMemory(kleeAddress, sizeInBytes, NULL, false, true, add_constraint);
}

S2EExecutor::S2EExecutor(S2E *s2e, TCGLLVMContext *tcgLLVMContext, const InterpreterOptions &opts,
                         InterpreterHandler *ie)
    : Executor(opts, ie, new DefaultSolverFactory(ie), tcgLLVMContext->getLLVMContext()), m_s2e(s2e),
      m_tcgLLVMContext(tcgLLVMContext), m_executeAlwaysKlee(false), m_forkProcTerminateCurrentState(false),
      m_inLoadBalancing(false), m_customClockSlowDown(1) {
    delete externalDispatcher;
    externalDispatcher = new S2EExternalDispatcher(tcgLLVMContext->getLLVMContext());

    LLVMContext &ctx = m_tcgLLVMContext->getLLVMContext();

/* Define globally accessible functions */
#define __DEFINE_EXT_FUNCTION(name) llvm::sys::DynamicLibrary::AddSymbol(#name, (void *) name);

#define __DEFINE_EXT_VARIABLE(name) llvm::sys::DynamicLibrary::AddSymbol(#name, (void *) &name);

    //__DEFINE_EXT_FUNCTION(raise_exception)
    //__DEFINE_EXT_FUNCTION(raise_exception_err)

    helper_register_symbols();

    __DEFINE_EXT_VARIABLE(g_s2e_concretize_io_addresses)
    __DEFINE_EXT_VARIABLE(g_s2e_concretize_io_writes)
    __DEFINE_EXT_VARIABLE(g_s2e_fork_on_symbolic_address)

    __DEFINE_EXT_VARIABLE(g_s2e_before_memory_access_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_after_memory_access_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_block_start_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_block_end_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_instruction_start_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_jump_start_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_lea_rip_relative_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_instruction_end_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_translate_register_access_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_exception_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_page_fault_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_tlb_miss_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_port_access_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_privilege_change_signals_count)
    __DEFINE_EXT_VARIABLE(g_s2e_on_page_directory_change_signals_count)

    __DEFINE_EXT_VARIABLE(g_s2e_enable_mmio_checks)

    __DEFINE_EXT_VARIABLE(s2e_kill_state)

    __DEFINE_EXT_FUNCTION(cpu_interrupt_handler)

    __DEFINE_EXT_FUNCTION(fprintf)
    __DEFINE_EXT_FUNCTION(sprintf)
    __DEFINE_EXT_FUNCTION(fputc)
    __DEFINE_EXT_FUNCTION(fwrite)

    __DEFINE_EXT_FUNCTION(floatx80_to_float64)
    __DEFINE_EXT_FUNCTION(float64_to_floatx80)
    __DEFINE_EXT_FUNCTION(int32_to_floatx80)
    __DEFINE_EXT_FUNCTION(int64_to_floatx80)
    __DEFINE_EXT_FUNCTION(floatx80_mul)
    __DEFINE_EXT_FUNCTION(floatx80_add)
    __DEFINE_EXT_FUNCTION(floatx80_compare_quiet)
    __DEFINE_EXT_FUNCTION(set_float_rounding_mode)

    __DEFINE_EXT_FUNCTION(cpu_x86_handle_mmu_fault)
    __DEFINE_EXT_FUNCTION(cpu_x86_update_cr0)
    __DEFINE_EXT_FUNCTION(cpu_x86_update_cr3)
    __DEFINE_EXT_FUNCTION(cpu_x86_update_cr4)
    __DEFINE_EXT_FUNCTION(cpu_x86_cpuid)
    __DEFINE_EXT_FUNCTION(cpu_get_apic_base)
    __DEFINE_EXT_FUNCTION(cpu_set_apic_base)
    __DEFINE_EXT_FUNCTION(cpu_get_apic_tpr)
    __DEFINE_EXT_FUNCTION(cpu_set_apic_tpr)
    __DEFINE_EXT_FUNCTION(cpu_smm_update)
    __DEFINE_EXT_FUNCTION(cpu_outb)
    __DEFINE_EXT_FUNCTION(cpu_outw)
    __DEFINE_EXT_FUNCTION(cpu_outl)
    __DEFINE_EXT_FUNCTION(cpu_inb)
    __DEFINE_EXT_FUNCTION(cpu_inw)
    __DEFINE_EXT_FUNCTION(cpu_inl)
    __DEFINE_EXT_FUNCTION(cpu_restore_state)
    __DEFINE_EXT_FUNCTION(cpu_abort)
    __DEFINE_EXT_FUNCTION(cpu_loop_exit)
    __DEFINE_EXT_FUNCTION(cpu_get_tsc)
    __DEFINE_EXT_FUNCTION(tb_find_pc)

    __DEFINE_EXT_FUNCTION(hw_breakpoint_insert)
    __DEFINE_EXT_FUNCTION(hw_breakpoint_remove)
    __DEFINE_EXT_FUNCTION(check_hw_breakpoints)

    __DEFINE_EXT_FUNCTION(tlb_flush_page)
    __DEFINE_EXT_FUNCTION(tlb_flush)

    __DEFINE_EXT_FUNCTION(io_readb_mmu)
    __DEFINE_EXT_FUNCTION(io_readw_mmu)
    __DEFINE_EXT_FUNCTION(io_readl_mmu)
    __DEFINE_EXT_FUNCTION(io_readq_mmu)

    __DEFINE_EXT_FUNCTION(io_writeb_mmu)
    __DEFINE_EXT_FUNCTION(io_writew_mmu)
    __DEFINE_EXT_FUNCTION(io_writel_mmu)
    __DEFINE_EXT_FUNCTION(io_writeq_mmu)

    __DEFINE_EXT_FUNCTION(se_ensure_symbolic)

    //__DEFINE_EXT_FUNCTION(s2e_on_tlb_miss)
    __DEFINE_EXT_FUNCTION(s2e_on_page_fault)
    __DEFINE_EXT_FUNCTION(s2e_is_port_symbolic)
    __DEFINE_EXT_FUNCTION(s2e_is_mmio_symbolic)
    __DEFINE_EXT_FUNCTION(se_is_mmio_symbolic_b)
    __DEFINE_EXT_FUNCTION(se_is_mmio_symbolic_w)
    __DEFINE_EXT_FUNCTION(se_is_mmio_symbolic_l)
    __DEFINE_EXT_FUNCTION(se_is_mmio_symbolic_q)

    __DEFINE_EXT_FUNCTION(s2e_on_privilege_change);
    __DEFINE_EXT_FUNCTION(s2e_on_page_fault);

    __DEFINE_EXT_FUNCTION(se_notdirty_mem_write)
    __DEFINE_EXT_FUNCTION(se_notdirty_mem_read)

    __DEFINE_EXT_FUNCTION(se_ismemfunc)
    __DEFINE_EXT_FUNCTION(phys_get_ops)
    __DEFINE_EXT_FUNCTION(is_notdirty_ops)

    __DEFINE_EXT_FUNCTION(ldub_phys)
    __DEFINE_EXT_FUNCTION(stb_phys)

    __DEFINE_EXT_FUNCTION(lduw_phys)
    __DEFINE_EXT_FUNCTION(stw_phys)

    __DEFINE_EXT_FUNCTION(ldl_phys)
    __DEFINE_EXT_FUNCTION(stl_phys)

    __DEFINE_EXT_FUNCTION(ldq_phys)
    __DEFINE_EXT_FUNCTION(stq_phys)

    ModuleOptions MOpts = ModuleOptions(vector<string>(),
                                        /* Optimize= */ true,
                                        /* CheckDivZero= */ false);
    /* Set module for the executor */
    bool persistentCacheEnabled = false;

    bool persistentCacheExists = llvm::sys::fs::exists(PersistentTbCache);

    std::string chosenModule;

    if (PersistentTbCache.size() && !persistentCacheExists) {
        llvm::errs() << "Cannot use persistent cache, " << PersistentTbCache << " does not exist\n";
    }

    if (PersistentTbCache.size() && persistentCacheExists) {
        chosenModule = PersistentTbCache;
        persistentCacheEnabled = true;
    } else {
#ifdef CONFIG_SYMBEX_MP
        char *filename = libcpu_find_file(FILE_TYPE_BIOS, "op_helper.bc." TARGET_ARCH);
#else
        char *filename = libcpu_find_file(FILE_TYPE_BIOS, "op_helper_sp.bc." TARGET_ARCH);
#endif
        assert(filename);
        chosenModule = filename;
        g_free(filename);
    }

    llvm::outs() << "Using module " << chosenModule << "\n";

    MOpts = ModuleOptions(vector<string>(1, chosenModule.c_str()),
                          /* Optimize= */ true, /* CheckDivZero= */ false, m_tcgLLVMContext->getFunctionPassManager());
    MOpts.Snapshot = persistentCacheEnabled;

    if (PersistentTbCache.size()) {
        KeepLLVMFunctions = true;
    }

    /* This catches obvious LLVM misconfigurations */
    Module *M = m_tcgLLVMContext->getModule();

    DataLayout TD(M);
    assert(M->getDataLayout().getPointerSizeInBits() == 64 &&
           "Something is broken in your LLVM build: LLVM thinks pointers are 32-bits!");

    s2e->getDebugStream() << "Current data layout: " << m_tcgLLVMContext->getModule()->getDataLayoutStr() << '\n';
    s2e->getDebugStream() << "Current target triple: " << m_tcgLLVMContext->getModule()->getTargetTriple() << '\n';

    setModule(m_tcgLLVMContext->getModule(), MOpts, false);

    if (UseFastHelpers && !persistentCacheEnabled) {
        disableConcreteLLVMHelpers();
    }

    /* Add dummy TB function declaration */
    if (!persistentCacheEnabled) {
        PointerType *tbFunctionArgTy = PointerType::get(IntegerType::get(ctx, 64), 0);
        FunctionType *tbFunctionTy = FunctionType::get(
            IntegerType::get(ctx, TCG_TARGET_REG_BITS),
            ArrayRef<Type *>(vector<Type *>(1, PointerType::get(IntegerType::get(ctx, 64), 0))), false);

        Function *tbFunction = Function::Create(tbFunctionTy, Function::PrivateLinkage, "s2e_dummyTbFunction",
                                                m_tcgLLVMContext->getModule());

        /* Create dummy main function containing just two instructions:
           a call to TB function and ret */
        Function *dummyMain =
            Function::Create(FunctionType::get(Type::getVoidTy(ctx), false), Function::ExternalLinkage,
                             "s2e_dummyMainFunction", m_tcgLLVMContext->getModule());

        BasicBlock *dummyMainBB = BasicBlock::Create(ctx, "entry", dummyMain);

        vector<Value *> tbFunctionArgs(1, ConstantPointerNull::get(tbFunctionArgTy));
        CallInst::Create(tbFunction, ArrayRef<Value *>(tbFunctionArgs), "tbFunctionCall", dummyMainBB);
        ReturnInst::Create(m_tcgLLVMContext->getLLVMContext(), dummyMainBB);

        kmodule->updateModuleWithFunction(dummyMain);
        m_dummyMain = kmodule->functionMap[dummyMain];
    } else {
        Function *dummyMain = kmodule->module->getFunction("s2e_dummyMainFunction");
        assert(dummyMain);
        m_dummyMain = kmodule->functionMap[dummyMain];
    }
#ifdef CONFIG_SYMBEX_MP
    Function *function;

    function = kmodule->module->getFunction("tcg_llvm_write_mem_io_vaddr");
    assert(function);
    addSpecialFunctionHandler(function, handlerWriteMemIoVaddr);

    function = kmodule->module->getFunction("tcg_llvm_before_memory_access");
    assert(function);
    addSpecialFunctionHandler(function, handlerBeforeMemoryAccess);

    function = kmodule->module->getFunction("tcg_llvm_after_memory_access");
    assert(function);
    addSpecialFunctionHandler(function, handlerAfterMemoryAccess);

    function = kmodule->module->getFunction("tcg_llvm_trace_port_access");
    assert(function);
    addSpecialFunctionHandler(function, handlerTracePortAccess);

    function = kmodule->module->getFunction("tcg_llvm_trace_mmio_access");
    assert(function);
    addSpecialFunctionHandler(function, handlerTraceMmioAccess);

#if 0
    // XXX: we need a mechanism to intercept indirect function calls
    function = kmodule->module->getFunction("s2e_on_tlb_miss");
    assert(function);
    addSpecialFunctionHandler(function, handlerOnTlbMiss);
#endif

    function = kmodule->module->getFunction("tcg_llvm_fork_and_concretize");
    assert(function);
    addSpecialFunctionHandler(function, handleForkAndConcretize);

    function = kmodule->module->getFunction("tcg_llvm_get_value");
    assert(function);
    addSpecialFunctionHandler(function, handleGetValue);

    FunctionType *traceInstTy = FunctionType::get(Type::getVoidTy(M->getContext()), false);
    function =
        dynamic_cast<Function *>(kmodule->module->getOrInsertFunction("tcg_llvm_trace_instruction", traceInstTy));
    assert(function);
    addSpecialFunctionHandler(function, handlerTraceInstruction);

    if (UseFastHelpers) {
        replaceExternalFunctionsWithSpecialHandlers();
    }

    m_tcgLLVMContext->initializeHelpers();

#endif
    m_tcgLLVMContext->initializeNativeCpuState();

    initializeStatistics();

    searcher = constructUserSearcher(*this);

    m_forceConcretizations = false;

    g_s2e_fork_on_symbolic_address = ForkOnSymbolicAddress;
    g_s2e_concretize_io_addresses = ConcretizeIoAddress;
    g_s2e_concretize_io_writes = ConcretizeIoWrites;

    concolicMode = ConcolicMode;

    if (UseFastHelpers) {
        if (!ForkOnSymbolicAddress) {
            s2e->getWarningsStream() << UseFastHelpers.ArgStr << " can only be used if " << ForkOnSymbolicAddress.ArgStr
                                     << " is enabled\n";
            exit(-1);
        }
    }

    if (SinglePathMode) {
        g_s2e_single_path_mode = 1;
        s2e->getWarningsStream() << "S2E will run in single path mode. Forking and symbolic execution not allowed.\n";
    }
}

void S2EExecutor::initializeStatistics() {
    if (StatsTracker::useStatistics()) {
        if (!statsTracker) {
            statsTracker = new S2EStatsTracker(*this, interpreterHandler->getOutputFilename("assembly.ll"));
        }

        statsTracker->writeHeaders();
    }
}

void S2EExecutor::flushTb() {
    tb_flush(env); // release references to TB functions
}

S2EExecutor::~S2EExecutor() {
    if (statsTracker)
        statsTracker->done();
}

S2EExecutionState *S2EExecutor::createInitialState() {
    assert(!processTree);

    /* Create initial execution state */
    S2EExecutionState *state = new S2EExecutionState(m_dummyMain);

    state->m_runningConcrete = true;
    state->m_active = true;
    state->setForking(EnableForking);

    states.insert(state);
    createStateSolver(*state);
    addedStates.insert(state);
    updateStates(state);

    processTree = new PTree(state);
    state->ptreeNode = processTree->root;

    /* Externally accessible global vars */
    /* XXX move away */
    addExternalObject(*state, &tcg_llvm_runtime, sizeof(tcg_llvm_runtime), false,
                      /* isUserSpecified = */ true,
                      /* isSharedConcrete = */ true,
                      /* isValueIgnored = */ true);

    addExternalObject(*state, (void *) tb_function_args, sizeof(tb_function_args), false,
                      /* isUserSpecified = */ true,
                      /* isSharedConcrete = */ true,
                      /* isValueIgnored = */ true);

#define __DEFINE_EXT_OBJECT_RO(name)                                 \
    predefinedSymbols.insert(std::make_pair(#name, (void *) &name)); \
    addExternalObject(*state, (void *) &name, sizeof(name), true, true, true)->setName(#name);

#define __DEFINE_EXT_OBJECT_RO_SYMB(name)                            \
    predefinedSymbols.insert(std::make_pair(#name, (void *) &name)); \
    addExternalObject(*state, (void *) &name, sizeof(name), true, true, false)->setName(#name);

    if (g_sqi.size != sizeof(g_sqi)) {
        abort();
    }

    __DEFINE_EXT_OBJECT_RO(g_sqi)
    __DEFINE_EXT_OBJECT_RO(env)
    __DEFINE_EXT_OBJECT_RO(g_s2e)
    __DEFINE_EXT_OBJECT_RO(g_s2e_state)

    __DEFINE_EXT_OBJECT_RO(cpu_single_env)
    __DEFINE_EXT_OBJECT_RO(loglevel)
    __DEFINE_EXT_OBJECT_RO(logfile)
    __DEFINE_EXT_OBJECT_RO_SYMB(parity_table)
    __DEFINE_EXT_OBJECT_RO_SYMB(rclw_table)
    __DEFINE_EXT_OBJECT_RO_SYMB(rclb_table)

    m_s2e->getInfoStream(state) << "Created initial state" << '\n';

    g_s2e_running_concrete = (char *) (&state->m_runningConcrete);
    g_s2e_running_exception_emulation_code = (char *) &state->m_runningExceptionEmulationCode;

    return state;
}

void S2EExecutor::initializeExecution(S2EExecutionState *state, bool executeAlwaysKlee) {
    m_executeAlwaysKlee = executeAlwaysKlee;

    initializeGlobals(*state);
    bindModuleConstants();

    initTimers();
    initializeStateSwitchTimer();
}

void S2EExecutor::registerCpu(S2EExecutionState *initialState, CPUX86State *cpuEnv) {
    std::cout << std::hex << "Adding CPU (addr = " << std::hex << cpuEnv << ", size = 0x" << sizeof(*cpuEnv) << ")"
              << std::dec << '\n';

    if (sizeof(*cpuEnv) != cpuEnv->size) {
        std::cerr << "Invalid cpu size structure\n";
        abort();
    }

    /* Add registers and eflags area as a true symbolic area */
    MemoryObject *symbolicRegs = addExternalObject(*initialState, cpuEnv, offsetof(CPUX86State, eip),
                                                   /* isReadOnly = */ false,
                                                   /* isUserSpecified = */ false,
                                                   /* isSharedConcrete = */ false);

    /* Add the rest of the structure as concrete-only area */
    MemoryObject *concreteRegs = addExternalObject(*initialState, ((uint8_t *) cpuEnv) + offsetof(CPUX86State, eip),
                                                   sizeof(CPUX86State) - offsetof(CPUX86State, eip),
                                                   /* isReadOnly = */ false,
                                                   /* isUserSpecified = */ true,
                                                   /* isSharedConcrete = */ true);

    initialState->m_registers.initialize(initialState->addressSpace, symbolicRegs, concreteRegs);
}

void S2EExecutor::registerSharedExternalObject(S2EExecutionState *state, void *address, unsigned size) {
    addExternalObject(*state, address, size, false,
                      /* isUserSpecified = */ true, true, true);
}

void S2EExecutor::registerRam(S2EExecutionState *initialState, MemoryDesc *region, uint64_t startAddress, uint64_t size,
                              uint64_t hostAddress, bool isSharedConcrete, bool saveOnContextSwitch, const char *name) {
#ifdef CONFIG_SYMBEX_MP

    assert(isSharedConcrete || !saveOnContextSwitch);
    assert(startAddress == (uint64_t) -1 || (startAddress & ~TARGET_PAGE_MASK) == 0);
    assert((size & ~TARGET_PAGE_MASK) == 0);
    assert((hostAddress & ~TARGET_PAGE_MASK) == 0);

    m_s2e->getDebugStream() << "Adding memory block (startAddr = " << hexval(startAddress)
                            << ", size = " << hexval(size) << ", hostAddr = " << hexval(hostAddress)
                            << ", isSharedConcrete=" << isSharedConcrete << ", name=" << name << ")\n";

    for (uint64_t addr = hostAddress; addr < hostAddress + size; addr += SE_RAM_OBJECT_SIZE) {

        MemoryObject *mo = addExternalObject(*initialState, (void *) addr, SE_RAM_OBJECT_SIZE, false,
                                             /* isUserSpecified = */ true, isSharedConcrete,
                                             isSharedConcrete && !saveOnContextSwitch && StateSharedMemory);

        mo->isMemoryPage = true;

        if (!isSharedConcrete) {
            mo->isSplittable = true;
            mo->doNotifyOnConcretenessChange = true;
        }

#ifdef S2E_DEBUG_MEMOBJECT_NAME
        std::stringstream ss;
        ss << name << "_" << std::hex << (addr - hostAddress);
        mo->setName(ss.str());
#endif

        if (isSharedConcrete && (saveOnContextSwitch || !StateSharedMemory)) {
            m_saveOnContextSwitch.push_back(mo);
        }
    }

    if (!isSharedConcrete) {
        // mprotecting does not actually free the RAM, it's still committed,
        // we need to explicitely unmap it.
        // mprotect((void*) hostAddress, size, PROT_NONE);
        if (munmap((void *) hostAddress, size) < 0) {
            m_s2e->getWarningsStream(NULL) << "Could not unmap host RAM\n";
            exit(-1);
        }

        // Make sure that the memory space is reserved and won't be used anymore
        // so that there are no conflicts with klee memory objects.
        void *newhost = mmap((void *) hostAddress, size, PROT_NONE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        if (newhost == MAP_FAILED || newhost != (void *) hostAddress) {
            m_s2e->getWarningsStream(NULL) << "Could not map host RAM\n";
            exit(-1);
        }

        m_unusedMemoryDescs.push_back(make_pair(hostAddress, size));
    }

    initialState->m_asCache.registerPool(hostAddress, size);
#endif
}

void S2EExecutor::registerDirtyMask(S2EExecutionState *state, uint64_t hostAddress, uint64_t size) {
    // Assume that dirty mask is small enough, so no need to split it in small pages
    MemoryObject *dirtyMask = g_s2e->getExecutor()->addExternalObject(*state, (void *) hostAddress, size, false,
                                                                      /* isUserSpecified = */ true, true, false);

    state->m_memory.initialize(&state->addressSpace, &state->m_asCache, &state->m_active, state, state, dirtyMask);

    g_se_dirty_mask_addend = state->mem()->getDirtyMaskStoreAddend();
}

void S2EExecutor::switchToConcrete(S2EExecutionState *state) {
    assert(!state->m_runningConcrete);

    if (PrintModeSwitch) {
        m_s2e->getInfoStream(state) << "Switching to concrete execution at pc = " << hexval(state->getPc()) << '\n';
    }

    /* Concretize any symbolic registers */
    if (m_forceConcretizations) {
        assert(false && "Deprecated");
    }

    // assert(os->isAllConcrete());
    state->m_registers.copySymbRegs(true);

    state->m_runningConcrete = true;
}

void S2EExecutor::switchToSymbolic(S2EExecutionState *state) {
    assert(state->m_runningConcrete);

    if (PrintModeSwitch) {
        m_s2e->getInfoStream(state) << "Switching to symbolic execution at pc = " << hexval(state->getPc()) << '\n';
    }

    // assert(os && os->isAllConcrete());

    // TODO: check that symbolic registers were not accessed
    // in shared location ! Ideas: use hw breakpoints, or instrument
    // translated code.

    state->m_registers.copySymbRegs(false);
    state->m_runningConcrete = false;
}

void S2EExecutor::doLoadBalancing() {
    if (states.size() < 2) {
        return;
    }

    // Don't bother copying stuff if it's obvious that it'll very likely fail
    if (m_s2e->getCurrentProcessCount() == m_s2e->getMaxProcesses()) {
        return;
    }

    std::vector<S2EExecutionState *> allStates;

    foreach2 (it, states.begin(), states.end()) {
        S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(*it);
        if (!s2estate->isZombie() && !s2estate->isPinned()) {
            allStates.push_back(s2estate);
        }
    }

    if (allStates.size() < 2) {
        return;
    }

    bool proceed = true;
    m_s2e->getCorePlugin()->onProcessForkDecide.emit(&proceed);
    if (!proceed) {
        return;
    }

    // Do the splitting before the fork, because we want to
    // let plugins modify the partition. Some plugins might
    // even want to keep a state in all instances.
    unsigned size = allStates.size();
    unsigned n = size / 2;

    // These two sets are the two partitions.
    StateSet parentSet, childSet;

    for (unsigned i = 0; i < n; ++i) {
        parentSet.insert(allStates[i]);
    }

    for (unsigned i = n; i < allStates.size(); ++i) {
        childSet.insert(allStates[i]);
    }

    m_s2e->getCorePlugin()->onStatesSplit.emit(parentSet, childSet);

    g_s2e->getDebugStream() << "LoadBalancing: starting\n";

    m_inLoadBalancing = true;

    unsigned parentId = m_s2e->getCurrentProcessIndex();
    m_s2e->getCorePlugin()->onProcessFork.emit(true, false, -1);
    int child = m_s2e->fork();
    if (child < 0) {
        // Fork did not succeed
        m_s2e->getCorePlugin()->onProcessFork.emit(false, false, -1);
        m_inLoadBalancing = false;
        return;
    }

    m_s2e->getCorePlugin()->onProcessFork.emit(false, child, parentId);

    g_s2e->getDebugStream() << "LoadBalancing: terminating states\n";

    /// Go through all the states and kill those that are
    /// not in the sets.
    StateSet &currentSet = child ? childSet : parentSet;

    for (auto state : allStates) {
        S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);
        if (!currentSet.count(s2estate)) {
            terminateStateAtFork(*s2estate);

            // This is important if we kill the current state
            s2estate->zombify();
        }
    }

    m_s2e->getCorePlugin()->onProcessForkComplete.emit(child);

    m_inLoadBalancing = false;
}

void S2EExecutor::stateSwitchTimerCallback(void *opaque) {
    S2EExecutor *c = (S2EExecutor *) opaque;

    assert(env->current_tb == NULL);

    if (g_s2e_state) {
        c->doLoadBalancing();
        S2EExecutionState *nextState = c->selectNextState(g_s2e_state);
        if (nextState) {
            // Create per state solver only when we're going to execute that state
            c->createStateSolver(*nextState);

            g_s2e_state = nextState;
        } else {
            // Do not reschedule the timer anymore
            return;
        }
    }

    libcpu_mod_timer(c->m_stateSwitchTimer, libcpu_get_clock_ms(host_clock) + 100);
}

void S2EExecutor::initializeStateSwitchTimer() {
    m_stateSwitchTimer = libcpu_new_timer_ms(host_clock, &stateSwitchTimerCallback, this);
    libcpu_mod_timer(m_stateSwitchTimer, libcpu_get_clock_ms(host_clock) + 100);
}

void S2EExecutor::resetStateSwitchTimer() {
    libcpu_mod_timer(m_stateSwitchTimer, libcpu_get_clock_ms(host_clock));
}

void S2EExecutor::doStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState) {
    assert(oldState || newState);
    assert(!oldState || oldState->m_active);
    assert(!newState || !newState->m_active);
    assert(!newState || !newState->m_runningConcrete);

    // Some state save/restore logic flushes the cache.
    // This can have bad effects in case of saving/restoring states
    // that were in the middle of a memory operation. Therefore,
    // we disable it here and re-enable after the new state has been activated.
    g_se_disable_tlb_flush = 1;

    // Clear the asynchronous request queue, which is not part of the KVM state
    s2e_kvm_flush_disk();

    cpu_disable_ticks();

    m_s2e->getInfoStream(oldState) << "Switching from state " << (oldState ? oldState->getID() : -1) << " to state "
                                   << (newState ? newState->getID() : -1) << '\n';

    uint64_t totalCopied = 0;
    uint64_t objectsCopied = 0;

    if (oldState) {
        if (VerboseStateSwitching) {
            m_s2e->getDebugStream(oldState) << "Saving state\n";
        }

        if (oldState->m_runningConcrete)
            switchToSymbolic(oldState);

        foreach2 (it, m_saveOnContextSwitch.begin(), m_saveOnContextSwitch.end()) {
            MemoryObject *mo = *it;

            const ObjectState *oldOS = oldState->addressSpace.findObject(mo);
            ObjectState *oldWOS = oldState->addressSpace.getWriteable(mo, oldOS);
            uint8_t *oldStore = oldWOS->getConcreteStore();
            assert(oldStore);
            memcpy(oldStore, (uint8_t *) mo->address, mo->size);
        }

        // XXX: specify which state should be used
        s2e_kvm_save_device_state();

        *oldState->m_timersState = timers_state;

        oldState->m_registers.saveConcreteState();
        oldState->m_active = false;
    }

    if (newState) {
        if (VerboseStateSwitching) {
            m_s2e->getDebugStream(newState) << "Restoring state\n";
        }

        timers_state = *newState->m_timersState;

        jmp_buf jmp_env;
        memcpy(&jmp_env, &env->jmp_env, sizeof(jmp_buf));

        newState->m_registers.restoreConcreteState();

        memcpy(&env->jmp_env, &jmp_env, sizeof(jmp_buf));

        newState->m_active = true;

        // Devices may need to write to memory, which can be done
        // after the state is activated
        // XXX: assigning g_s2e_state here is ugly but is required for restoreDeviceState...
        g_s2e_state = newState;
        g_se_dirty_mask_addend = g_s2e_state->mem()->getDirtyMaskStoreAddend();

        // XXX: specify which state should be used
        s2e_kvm_restore_device_state();

        foreach2 (it, m_saveOnContextSwitch.begin(), m_saveOnContextSwitch.end()) {
            MemoryObject *mo = *it;
            const ObjectState *newOS = newState->addressSpace.findObject(mo);
            const uint8_t *newStore = newOS->getConcreteStore();
            assert(newStore);
            memcpy((uint8_t *) mo->address, newStore, mo->size);
            totalCopied += mo->size;
            objectsCopied++;
        }
    }

    cpu_enable_ticks();

    if (VerboseStateSwitching) {
        s2e_debug_print("Copied %d (count=%d)\n", totalCopied, objectsCopied);
    }

    if (FlushTBsOnStateSwitch)
        tb_flush(env);

    /**
     * Forking has saved the pointer to the current tb. By the time the state
     * resumes, this pointer might have become invalid. We must clear it here.
     */
    env->current_tb = NULL;

    g_se_disable_tlb_flush = 0;

    // m_s2e->getCorePlugin()->onStateSwitch.emit(oldState, newState);
}

ExecutionState *S2EExecutor::selectSearcherState(S2EExecutionState *state) {
    ExecutionState *newState = NULL;

    if (!searcher->empty()) {
        newState = &searcher->selectState();
    }

    if (!newState) {
        m_s2e->getWarningsStream() << "All states were terminated" << '\n';
        foreach2 (it, m_deletedStates.begin(), m_deletedStates.end()) {
            S2EExecutionState *s = *it;
            // Leave the current state in a zombie form to let the process exit gracefully.
            if (s != g_s2e_state) {
                unrefS2ETb(s->m_lastS2ETb);
                s->m_lastS2ETb = NULL;
                delete s;
            }
        }
        m_deletedStates.clear();
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        exit(0);
    }

    return newState;
}

S2EExecutionState *S2EExecutor::selectNextState(S2EExecutionState *state) {
    assert(state->m_active);
    updateStates(state);

    /* Prevent state switching */
    if (state->isStateSwitchForbidden() && !state->isZombie()) {
        return state;
    }

    ExecutionState *nstate = selectSearcherState(state);
    if (nstate == NULL) {
        return NULL;
    }

    // This assertion must go before the cast to S2EExecutionState.
    // In case the searcher returns a bogus state, this allows
    // spotting it immediately. The dynamic cast however, might cause
    // memory corruptions.
    assert(states.find(nstate) != states.end());

    S2EExecutionState *newState = dynamic_cast<S2EExecutionState *>(nstate);

    assert(newState);

    assert(!newState->isZombie());

    newState->yield(false);

    if (!state->m_active) {
        /* Current state might be switched off by merge method */
        state = NULL;
    }

    if (newState != state) {
        doStateSwitch(state, newState);
        g_s2e->getCorePlugin()->onStateSwitch.emit(state, newState);
    }

    // We can't free the state immediately if it is the current state.
    // Do it now.
    foreach2 (it, m_deletedStates.begin(), m_deletedStates.end()) {
        S2EExecutionState *s = *it;
        assert(s != newState);
        unrefS2ETb(s->m_lastS2ETb);
        s->m_lastS2ETb = NULL;
        delete s;
    }
    m_deletedStates.clear();

    updateConcreteFastPath(newState);

    return newState;
}

/** Simulate start of function execution, creating KLEE structs of required */
void S2EExecutor::prepareFunctionExecution(S2EExecutionState *state, llvm::Function *function,
                                           const std::vector<klee::ref<klee::Expr>> &args) {
    KFunction *kf;
    typeof(kmodule->functionMap.begin()) it = kmodule->functionMap.find(function);
    if (it != kmodule->functionMap.end()) {
        kf = it->second;
    } else {

        unsigned cIndex = kmodule->constants.size();
        kf = kmodule->updateModuleWithFunction(function);

        for (unsigned i = 0; i < kf->numInstructions; ++i)
            bindInstructionConstants(kf->instructions[i]);

        /* Update global functions (new functions can be added
           while creating added function) */
        for (Module::iterator i = kmodule->module->begin(), ie = kmodule->module->end(); i != ie; ++i) {
            Function *f = &*i;
            klee::ref<klee::ConstantExpr> addr(0);

            // If the symbol has external weak linkage then it is implicitly
            // not defined in this module; if it isn't resolvable then it
            // should be null.
            if (f->hasExternalWeakLinkage() && !externalDispatcher->resolveSymbol(f->getName().str())) {
                addr = Expr::createPointer(0);
            } else {
                addr = Expr::createPointer((uintptr_t)(void *) f);
                legalFunctions.insert((uint64_t)(uintptr_t)(void *) f);
            }

            globalAddresses.insert(std::make_pair(f, addr));
        }

        kmodule->constantTable.resize(kmodule->constants.size());

        for (unsigned i = cIndex; i < kmodule->constants.size(); ++i) {
            Cell &c = kmodule->constantTable[i];
            c.value = evalConstant(kmodule->constants[i]);
        }
    }

    /* Emulate call to a TB function */
    state->prevPC = state->pc;

    state->pushFrame(state->pc, kf);
    state->pc = kf->instructions;

    /* Pass argument */
    for (unsigned i = 0; i < args.size(); ++i)
        bindArgument(kf, i, *state, args[i]);
}

inline bool S2EExecutor::executeInstructions(S2EExecutionState *state, unsigned callerStackSize) {
    try {
        while (state->stack.size() != callerStackSize) {
            assert(!g_s2e_fast_concrete_invocation && !*g_s2e_running_concrete);

            ++state->m_stats.m_statInstructionCountSymbolic;

            KInstruction *ki = state->pc;

            if (PrintLLVMInstructions) {
                m_s2e->getDebugStream(state) << "executing " << ki->inst->getParent()->getParent()->getName().str()
                                             << ": " << *ki->inst << '\n';
            }

            stepInstruction(*state);
            executeInstruction(*state, ki);

            updateStates(state);

            // Handle the case where we killed the current state inside processFork
            if (m_forkProcTerminateCurrentState) {
                state->regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
                state->zombify();
                m_forkProcTerminateCurrentState = false;
                return true;
            }
        }
    } catch (CpuExitException &) {
        updateStates(state);
        // assert(addedStates.empty());
        return true;
    }

    // The TB finished executing normally
    if (callerStackSize == 1) {
        state->prevPC = 0;
        state->pc = m_dummyMain->instructions;
    }

    return false;
}

bool S2EExecutor::finalizeTranslationBlockExec(S2EExecutionState *state) {
    if (!state->m_needFinalizeTBExec)
        return false;

    state->m_needFinalizeTBExec = false;
    state->m_forkAborted = false;

    assert(state->stack.size() != 1);

    assert(!state->m_runningConcrete);

    if (VerboseTbFinalize) {
        m_s2e->getDebugStream(state) << "Finalizing TB execution\n";
        foreach2 (it, state->stack.begin(), state->stack.end()) {
            const StackFrame &fr = *it;
            m_s2e->getDebugStream() << fr.kf->function->getName().str() << '\n';
        }
    }

    /**
     * TBs can fork anywhere and the remainder can also throw exceptions.
     * Should exit the CPU loop in this case.
     */
    bool ret = executeInstructions(state);

    if (VerboseTbFinalize) {
        m_s2e->getDebugStream(state) << "Done finalizing TB execution, new pc=" << hexval(state->getPc()) << "\n";
    }

    /**
     * Memory topology may change on state switches.
     * Ensure that there are no bad mappings left.
     */
    tlb_flush(env, 1);

    return ret;
}

#ifdef _WIN32

extern "C" volatile LONG g_signals_enabled;

typedef int sigset_t;

static void s2e_disable_signals(sigset_t *oldset) {
    while (InterlockedCompareExchange(&g_signals_enabled, 0, 1) == 0)
        ;
}

static void s2e_enable_signals(sigset_t *oldset) {
    g_signals_enabled = 1;
}

#else

static void s2e_disable_signals(sigset_t *oldset) {
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, oldset);
}

static void s2e_enable_signals(sigset_t *oldset) {
    sigprocmask(SIG_SETMASK, oldset, NULL);
}

#endif

void S2EExecutor::updateSlowDownFactor() {
    if (!g_s2e_fast_concrete_invocation) {
        // XXX: adapt scaling dynamically.
        int slowdown = 1;

        if (m_customClockSlowDown != 1) {
            slowdown = m_customClockSlowDown;
        } else {
            slowdown = UseFastHelpers ? ClockSlowDownFastHelpers : ClockSlowDown;
        }
        cpu_enable_scaling(slowdown);
    } else {
        int new_scaling = timers_state.clock_scale / 2;
        if (new_scaling == 0)
            new_scaling = 1;

        if (m_customClockSlowDown != 1) {
            new_scaling = m_customClockSlowDown;
        }
        cpu_enable_scaling(new_scaling);
    }
}

void S2EExecutor::updateConcreteFastPath(S2EExecutionState *state) {
    bool allConcrete = state->getSymbolicRegistersMask() == 0;
    g_s2e_fast_concrete_invocation = (allConcrete) && (state->m_toRunSymbolically.size() == 0) &&
                                     (state->m_startSymbexAtPC == (uint64_t) -1) &&

                                     // Check that we are not currently running in KLEE
                                     //(CPU register access from concrete code depend on g_s2e_fast_concrete_invocation)
                                     (state->stack.size() == 1) &&

                                     (m_executeAlwaysKlee == false);

    g_s2e_running_concrete = (char *) &state->m_runningConcrete;
    g_s2e_running_exception_emulation_code = (char *) &state->m_runningExceptionEmulationCode;

    updateSlowDownFactor();
}

uintptr_t S2EExecutor::executeTranslationBlockKlee(S2EExecutionState *state, TranslationBlock *tb) {
    tb_function_args[0] = env;
    tb_function_args[1] = 0;
    tb_function_args[2] = 0;

    assert(state->m_active && !state->m_runningConcrete);
    assert(state->stack.size() == 1);
    assert(state->pc == m_dummyMain->instructions);

    ++state->m_stats.m_statTranslationBlockSymbolic;

    /* Generate LLVM code if necessary */
    if (!tb->llvm_function) {
        se_tb_gen_llvm(env, tb);
        assert(tb->llvm_function);
    }

    if (tb->se_tb != state->m_lastS2ETb) {
        unrefS2ETb(state->m_lastS2ETb);
        state->m_lastS2ETb = static_cast<S2ETranslationBlock *>(tb->se_tb);
        refS2ETb(state->m_lastS2ETb);
    }

    /* Prepare function execution */
    prepareFunctionExecution(state, static_cast<Function *>(tb->llvm_function),
                             std::vector<klee::ref<Expr>>(1, Expr::createPointer((uint64_t) tb_function_args)));

    if (executeInstructions(state)) {
        throw CpuExitException();
    }

    // XXX: TBs may be reused, persisted, etc.
    // The returned value stored has no meaning (could refer to
    // flushed TBs, etc.).
    return 0;
}

uintptr_t S2EExecutor::executeTranslationBlockConcrete(S2EExecutionState *state, TranslationBlock *tb) {
    assert(state->m_active && state->m_runningConcrete);
    ++state->m_stats.m_statTranslationBlockConcrete;

    uintptr_t ret = 0;
    memcpy(s2e_cpuExitJmpBuf, env->jmp_env, sizeof(env->jmp_env));

    if (setjmp(env->jmp_env)) {
        memcpy(env->jmp_env, s2e_cpuExitJmpBuf, sizeof(env->jmp_env));
        throw CpuExitException();
    } else {
        ret = tcg_libcpu_tb_exec(env, tb->tc_ptr);
    }

    memcpy(env->jmp_env, s2e_cpuExitJmpBuf, sizeof(env->jmp_env));
    return ret;
}

static inline void se_tb_reset_jump(TranslationBlock *tb, unsigned int n) {
    TranslationBlock *tb1, *tb_next, **ptb;
    unsigned int n1;

    tb1 = tb->jmp_next[n];
    if (tb1 != NULL) {
        /* find head of list */
        for (;;) {
            n1 = (intptr_t) tb1 & 3;
            tb1 = (TranslationBlock *) ((intptr_t) tb1 & ~3);
            if (n1 == 2)
                break;
            tb1 = tb1->jmp_next[n1];
        }
        /* we are now sure now that tb jumps to tb1 */
        tb_next = tb1;

        /* remove tb from the jmp_first list */
        ptb = &tb_next->jmp_first;
        for (;;) {
            tb1 = *ptb;
            n1 = (intptr_t) tb1 & 3;
            tb1 = (TranslationBlock *) ((intptr_t) tb1 & ~3);
            if (n1 == n && tb1 == tb)
                break;
            ptb = &tb1->jmp_next[n1];
        }
        *ptb = tb->jmp_next[n];
        tb->jmp_next[n] = NULL;

        /* suppress the jump to next tb in generated code */
        tb_set_jmp_target(tb, n, (uintptr_t)(tb->tc_ptr + tb->tb_next_offset[n]));
        tb->se_tb_next[n] = NULL;
    }
}

// XXX: inline causes compiler internal errors
static void se_tb_reset_jump_smask(TranslationBlock *tb, unsigned int n, uint64_t smask, int depth = 0) {
    TranslationBlock *tb1 = tb->se_tb_next[n];
    sigset_t oldset;
    if (depth == 0) {
        s2e_disable_signals(&oldset);
    }

    if (tb1) {
        if (depth > 2 || (smask & tb1->reg_rmask) || (smask & tb1->reg_wmask) || (tb1->helper_accesses_mem & 4)) {
            se_tb_reset_jump(tb, n);
        } else if (tb1 != tb) {
            se_tb_reset_jump_smask(tb1, 0, smask, depth + 1);
            se_tb_reset_jump_smask(tb1, 1, smask, depth + 1);
        }
    }

    if (depth == 0) {
        s2e_enable_signals(&oldset);
    }
}

uintptr_t S2EExecutor::executeTranslationBlockSlow(struct CPUX86State *env1, struct TranslationBlock *tb) {
    try {
        uintptr_t ret = g_s2e->getExecutor()->executeTranslationBlock(g_s2e_state, tb);
        return ret;
    } catch (s2e::CpuExitException &) {
        g_s2e->getExecutor()->updateStates(g_s2e_state);
        longjmp(env->jmp_env, 1);
    }
}

uintptr_t S2EExecutor::executeTranslationBlockFast(struct CPUX86State *env1, struct TranslationBlock *tb) {
    env = env1;
    g_s2e_state->setRunningExceptionEmulationCode(false);

    if (likely(g_s2e_fast_concrete_invocation)) {
        if (unlikely(!g_s2e_state->isRunningConcrete())) {
            S2EExecutor *executor = g_s2e->getExecutor();
            executor->updateConcreteFastPath(g_s2e_state);
            assert(g_s2e_fast_concrete_invocation);
            executor->switchToConcrete(g_s2e_state);
        }
        return tcg_libcpu_tb_exec(env, tb->tc_ptr);
    } else {
        return executeTranslationBlockSlow(env, tb);
    }
}

uintptr_t S2EExecutor::executeTranslationBlock(S2EExecutionState *state, TranslationBlock *tb) {
    // Avoid incrementing stats every time, very expensive.
    static unsigned doStatsIncrementCount = 0;
    assert(state->isActive());

    updateConcreteFastPath(state);

    bool executeKlee = m_executeAlwaysKlee;

    /* Think how can we optimize if symbex is disabled */
    if (true /* state->m_symbexEnabled*/) {
        if (state->m_startSymbexAtPC != (uint64_t) -1) {
            executeKlee |= (state->getPc() == state->m_startSymbexAtPC);
            state->m_startSymbexAtPC = (uint64_t) -1;
        }

        // XXX: hack to run code symbolically that may be delayed because of interrupts.
        // Size check is important to avoid expensive calls to getPc/getPid in the common case
        if (state->m_toRunSymbolically.size() > 0 &&
            state->m_toRunSymbolically.find(std::make_pair(state->getPc(), state->getPageDir())) !=
                state->m_toRunSymbolically.end()) {
            executeKlee = true;
            state->m_toRunSymbolically.erase(std::make_pair(state->getPc(), state->getPageDir()));
        }

        if (!executeKlee) {
            // XXX: This should be fixed to make sure that helpers do not read/write corrupted data
            // because they think that execution is concrete while it should be symbolic (see issue #30).
            if (!m_forceConcretizations) {
                /* We can not execute TB natively if it reads any symbolic regs */
                uint64_t smask = state->getSymbolicRegistersMask();
                if (smask || (tb->helper_accesses_mem & 4)) {
                    if ((smask & tb->reg_rmask) || (smask & tb->reg_wmask) || (tb->helper_accesses_mem & 4)) {
                        /* TB reads symbolic variables */
                        executeKlee = true;

                    } else {
                        se_tb_reset_jump_smask(tb, 0, smask);
                        se_tb_reset_jump_smask(tb, 1, smask);
                    }
                }
            } // forced concretizations
        }
    }

    if (executeKlee) {
        if (state->m_runningConcrete) {
            if (EnableTimingLog) {
                TimerStatIncrementer t(stats::concreteModeTime);
            }
            switchToSymbolic(state);
        }

        if (EnableTimingLog) {
            TimerStatIncrementer t(stats::symbolicModeTime);
        }

        return executeTranslationBlockKlee(state, tb);

    } else {
        if (!state->m_runningConcrete)
            switchToConcrete(state);

        if (EnableTimingLog) {
            if (!((++doStatsIncrementCount) & 0xFFF)) {
                TimerStatIncrementer t(stats::concreteModeTime);
            }
        }

        return executeTranslationBlockConcrete(state, tb);
    }
}

void S2EExecutor::cleanupTranslationBlock(S2EExecutionState *state) {
    assert(state->m_active);

    if (state->m_forkAborted) {
        return;
    }

    while (state->stack.size() != 1)
        state->popFrame();

    state->prevPC = 0;
    state->pc = m_dummyMain->instructions;
}

klee::ref<klee::Expr> S2EExecutor::executeFunction(S2EExecutionState *state, llvm::Function *function,
                                                   const std::vector<klee::ref<klee::Expr>> &args) {
    assert(!state->m_runningConcrete);
    assert(!state->prevPC);
    assert(state->stack.size() == 1);

    /* Update state */
    KInstIterator callerPC = state->pc;
    uint32_t callerStackSize = state->stack.size();

    /* Prepare function execution */
    prepareFunctionExecution(state, function, args);

    /* Execute */
    if (executeInstructions(state, callerStackSize)) {
        throw CpuExitException();
    }

    if (callerPC == m_dummyMain->instructions) {
        assert(state->stack.size() == 1);
        state->prevPC = 0;
        state->pc = callerPC;
    }

    klee::ref<Expr> resExpr(0);
    if (function->getReturnType()->getTypeID() != Type::VoidTyID)
        resExpr = getDestCell(*state, state->pc).value;

    return resExpr;
}

klee::ref<klee::Expr> S2EExecutor::executeFunction(S2EExecutionState *state, const std::string &functionName,
                                                   const std::vector<klee::ref<klee::Expr>> &args) {
    llvm::Function *function = kmodule->module->getFunction(functionName);
    assert(function && "function with given name do not exists in LLVM module");
    return executeFunction(state, function, args);
}

void S2EExecutor::deleteState(klee::ExecutionState *state) {
    assert(dynamic_cast<S2EExecutionState *>(state));
    processTree->remove(state->ptreeNode);
    m_deletedStates.push_back(static_cast<S2EExecutionState *>(state));
}

void S2EExecutor::notifyFork(ExecutionState &originalState, klee::ref<Expr> &condition, Executor::StatePair &targets) {
    if (targets.first == NULL || targets.second == NULL) {
        return;
    }

    std::vector<S2EExecutionState *> newStates(2);
    std::vector<klee::ref<Expr>> newConditions(2);

    S2EExecutionState *state = static_cast<S2EExecutionState *>(&originalState);
    newStates[0] = static_cast<S2EExecutionState *>(targets.first);
    newStates[1] = static_cast<S2EExecutionState *>(targets.second);

    newConditions[0] = condition;
    newConditions[1] = klee::NotExpr::create(condition);

    try {
        m_s2e->getCorePlugin()->onStateFork.emit(state, newStates, newConditions);
    } catch (CpuExitException e) {
        if (state->stack.size() != 1) {
            state->m_needFinalizeTBExec = true;
            state->m_forkAborted = true;
        }
        throw e;
    }
}

S2EExecutor::StatePair S2EExecutor::fork(ExecutionState &current, klee::ref<Expr> condition, bool isInternal,
                                         bool deterministic, bool keepConditionTrueInCurrentState) {
    S2EExecutionState *currentState = dynamic_cast<S2EExecutionState *>(&current);
    assert(currentState);
    assert(!currentState->m_runningConcrete);

    StatePair res;

    if (currentState->forkDisabled && !dyn_cast<klee::ConstantExpr>(condition)) {
        g_s2e->getDebugStream(currentState) << "fork disabled\n";
    }

    bool forkOk = true;
    g_s2e->getCorePlugin()->onStateForkDecide.emit(currentState, &forkOk);

    bool oldForkStatus = currentState->forkDisabled;
    if (!forkOk && !currentState->forkDisabled) {
        currentState->forkDisabled = true;
    }

    if (ConcolicMode) {
        res = Executor::concolicFork(current, condition, isInternal, keepConditionTrueInCurrentState);
    } else {
        res = Executor::fork(current, condition, isInternal, deterministic, keepConditionTrueInCurrentState);
    }

    currentState->forkDisabled = oldForkStatus;

    if (!(res.first && res.second)) {
        return res;
    }

    S2EExecutionState *newStates[2];
    newStates[0] = static_cast<S2EExecutionState *>(res.first);
    newStates[1] = static_cast<S2EExecutionState *>(res.second);

    klee::ref<Expr> newConditions[2];
    newConditions[0] = condition;
    newConditions[1] = klee::NotExpr::create(condition);

    llvm::raw_ostream &out = m_s2e->getInfoStream(currentState);
    out << "Forking state " << currentState->getID() << " at pc = " << hexval(currentState->getPc())
        << " at pagedir = " << hexval(currentState->getPageDir()) << '\n';

    for (unsigned i = 0; i < 2; ++i) {
        if (VerboseFork) {
            out << "    state " << newStates[i]->getID();
            out << " with condition " << newConditions[i] << '\n';
        } else {
            out << "    state " << newStates[i]->getID() << "\n";
        }

        // Handled in ::branch
        if (newStates[i] != currentState) {
            newStates[i]->m_needFinalizeTBExec = true;
            newStates[i]->m_active = false;
        }
    }

    if (VerboseFork) {
        std::stringstream ss;
        printStack(*currentState, NULL, ss);
        m_s2e->getDebugStream() << "Stack frame at fork:" << '\n' << ss.str() << "\n";
    }

    return res;
}

/// \brief Fork state
///
/// Fork current state and return states in which condition
/// holds / does not hold. One of the states is necessarily the current
/// state, and one of the states may be null.
///
/// \note Do not use \p keepConditionTrueInCurrentState with seed state because
/// concolic values will be recomputed.
///
/// \param state current state
/// \param condition fork condition
/// \param keepConditionTrueInCurrentState set true if you want condition to hold in current state
/// \return state pair
///
S2EExecutor::StatePair S2EExecutor::forkCondition(S2EExecutionState *state, klee::ref<Expr> condition,
                                                  bool keepConditionTrueInCurrentState) {
    S2EExecutor::StatePair sp = fork(*state, condition, false, true, keepConditionTrueInCurrentState);
    notifyFork(*state, condition, sp);
    return sp;
}

/// \brief Fork state for each value
///
/// For every value from \p values: fork a new state with constraint
/// (\p expr == value).
///
/// \note In concolic mode, if original state is a seed state and
/// if constraint evaluates to true, no fork will be made. Original
/// state will be returned instead of forked state.
///
/// \todo Allow cloning of non active state and do not use
/// keepConditionTrueInCurrentState option.
///
/// \param state Original state to fork from
/// \param isSeedState True if original state is a seed state (contains
/// unconstrained concolic values that must be preserved)
/// \param expr Expression which will equal desired value in the forked state
/// \param values List of desired expression values
/// \return List of forked states. State index equals index of desired value.
/// State pointer will be NULL when forked state is infeasible.
///
std::vector<ExecutionState *> S2EExecutor::forkValues(S2EExecutionState *state, bool isSeedState,
                                                      klee::ref<klee::Expr> expr,
                                                      const std::vector<klee::ref<klee::Expr>> &values) {
    std::vector<ExecutionState *> ret;

    foreach2 (it, values.begin(), values.end()) {
        klee::ref<klee::Expr> condition = E_NEQ(expr, *it);

        if (isSeedState) {
            klee::ref<klee::Expr> eval = state->concolics->evaluate(condition);
            klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(eval);
            assert(ce && "Could not evaluate expression to constant");
            if (ce->isFalse()) {
                // expr equals value in seed state
                // do not recompute initial values in seed state
                ret.push_back(state);
                continue;
            }
        }

        StatePair sp = fork(*state, condition, true, true, true);
        notifyFork(*state, condition, sp);

        ret.push_back(sp.second);

        if (!sp.first) {
            // expr always equals value, no point in trying other values
            foreach2 (it2, it + 1, values.end()) { ret.push_back(NULL); }
            return ret;
        }

        // Ensure expr != value in current state. Then we'll be able to fork with next possible value.
        // Forking of branched state is forbidden (see assertion in S2EExecutionState::clone)
        assert(sp.first == state && "Condition must evaluate to True in current state");
    }

    return ret;
}

/**
 * Called from klee::Executor when the engine is about to fork
 * the current state.
 */
void S2EExecutor::notifyBranch(ExecutionState &state) {
    S2EExecutionState *s2eState = dynamic_cast<S2EExecutionState *>(&state);

    /* Checkpoint the device state before branching */
    s2e_kvm_flush_disk();

    s2eState->m_tlb.clearTlbOwnership();

    /**
     * These objects must be saved before the cpu state, because
     * getWritable() may modify the TLB.
     */
    foreach2 (it, m_saveOnContextSwitch.begin(), m_saveOnContextSwitch.end()) {
        MemoryObject *mo = *it;
        const ObjectState *os = s2eState->addressSpace.findObject(mo);
        ObjectState *wos = s2eState->addressSpace.getWriteable(mo, os);
        uint8_t *store = wos->getConcreteStore();
        assert(store);
        memcpy(store, (uint8_t *) mo->address, mo->size);
    }

#if defined(SE_ENABLE_PHYSRAM_TLB)
    s2eState->m_tlb.clearRamTlb();
#endif

    s2eState->m_registers.saveConcreteState();

    cpu_disable_ticks();
    s2e_kvm_save_device_state();
    *s2eState->m_timersState = timers_state;
    cpu_enable_ticks();
}

void S2EExecutor::branch(klee::ExecutionState &state, const vector<klee::ref<Expr>> &conditions,
                         vector<ExecutionState *> &result) {
    S2EExecutionState *s2eState = dynamic_cast<S2EExecutionState *>(&state);
    assert(!s2eState->m_runningConcrete);

    Executor::branch(state, conditions, result);

    unsigned n = conditions.size();

    vector<S2EExecutionState *> newStates;
    vector<klee::ref<Expr>> newConditions;

    newStates.reserve(n);
    newConditions.reserve(n);

    for (unsigned i = 0; i < n; ++i) {
        if (result[i]) {
            assert(dynamic_cast<S2EExecutionState *>(result[i]));
            newStates.push_back(static_cast<S2EExecutionState *>(result[i]));
            newConditions.push_back(conditions[i]);

            if (result[i] != &state) {
                S2EExecutionState *s = static_cast<S2EExecutionState *>(result[i]);
                s->m_needFinalizeTBExec = true;
                s->m_active = false;
            }
        }
    }

    /*if(newStates.size() > 1) {
        doStateFork(static_cast<S2EExecutionState*>(&state),
                       newStates, newConditions);
    }*/
}

bool S2EExecutor::merge(klee::ExecutionState &_base, klee::ExecutionState &_other) {
    assert(dynamic_cast<S2EExecutionState *>(&_base));
    assert(dynamic_cast<S2EExecutionState *>(&_other));
    S2EExecutionState &base = static_cast<S2EExecutionState &>(_base);
    S2EExecutionState &other = static_cast<S2EExecutionState &>(_other);

    /* Ensure that both states are inactive, otherwise merging will not work */
    bool s1 = false, s2 = false;
    if (base.m_active) {
        s1 = true;
        doStateSwitch(&base, NULL);
    }

    if (other.m_active) {
        s2 = true;
        doStateSwitch(&other, NULL);
    }

    bool result;
    if (base.merge(other)) {
        m_s2e->getInfoStream(&base) << "Merged with state " << other.getID() << '\n';
        result = true;
    } else {
        m_s2e->getDebugStream(&base) << "Merge with state " << other.getID() << " failed" << '\n';
        result = false;
    }

    // Reactivate the state
    if (s1) {
        doStateSwitch(NULL, &base);
    }

    if (s2) {
        doStateSwitch(NULL, &other);
    }

    if (result) {
        g_s2e->getCorePlugin()->onStateMerge.emit(&base, &other);
    }

    return result;
}

void S2EExecutor::terminateStateEarly(klee::ExecutionState &state, const llvm::Twine &message) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(&state);
    m_s2e->getInfoStream(s2estate) << "Terminating state early: " << message << "\n";
    terminateState(state);
}

void S2EExecutor::terminateState(ExecutionState &s) {
    S2EExecutionState &state = static_cast<S2EExecutionState &>(s);

    klee::stats::completedPaths += 1;

    m_s2e->getCorePlugin()->onStateKill.emit(&state);

    terminateStateAtFork(state);
    state.zombify();

    g_s2e->getWarningsStream().flush();
    g_s2e->getDebugStream().flush();

    // No need for exiting the loop if we kill another state.
    if (!m_inLoadBalancing && (&state == g_s2e_state)) {
        state.regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
        throw CpuExitException();
    }
}

/**
 * Yield the current state.
 * This will force to call the searcher to select the next state.
 * The next state may or may not be the same as the one that yielded.
 * It is up to the caller to define a searcher policy
 * (e.g., enforce that another different state is scheduled).
 * yieldState() only provides a mechanism.
 */
void S2EExecutor::yieldState(ExecutionState &s) {
    S2EExecutionState &state = static_cast<S2EExecutionState &>(s);

    m_s2e->getInfoStream(&state) << "Yielding state " << state.getID() << "\n";

    state.yield(true);

    // Stop current execution
    state.regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
    throw CpuExitException();
}

void S2EExecutor::terminateStateAtFork(S2EExecutionState &state) {
    Executor::terminateState(state);
}

inline void S2EExecutor::setCCOpEflags(S2EExecutionState *state) {
    uint32_t cc_op = 0;

    // Check wether any of cc_op, cc_src, cc_dst or cc_tmp are symbolic
    if (state->m_registers.flagsRegistersAreSymbolic() || m_executeAlwaysKlee) {
        // call set_cc_op_eflags only if cc_op is symbolic or cc_op != CC_OP_EFLAGS
        bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(cc_op), &cc_op, sizeof(cc_op));
        if (!ok || cc_op != CC_OP_EFLAGS) {
            try {
                if (state->m_runningConcrete)
                    switchToSymbolic(state);
                if (EnableTimingLog) {
                    TimerStatIncrementer t(stats::symbolicModeTime);
                }

                executeFunction(state, "helper_set_cc_op_eflags");
            } catch (s2e::CpuExitException &) {
                updateStates(state);
                longjmp(env->jmp_env, 1);
            }
        }
    } else {
        bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(cc_op), &cc_op, sizeof(cc_op));
        assert(ok);
        if (cc_op != CC_OP_EFLAGS) {
            if (!state->m_runningConcrete)
                switchToConcrete(state);
            // TimerStatIncrementer t(stats::concreteModeTime);
            helper_set_cc_op_eflags();
        }
    }
}

inline void S2EExecutor::doInterrupt(S2EExecutionState *state, int intno, int is_int, int error_code, uint64_t next_eip,
                                     int is_hw) {
    if (state->m_registers.allConcrete() && !m_executeAlwaysKlee) {
        if (!state->m_runningConcrete)
            switchToConcrete(state);
        // TimerStatIncrementer t(stats::concreteModeTime);
        se_do_interrupt_all(intno, is_int, error_code, next_eip, is_hw);
    } else {
        if (state->m_runningConcrete)
            switchToSymbolic(state);
        std::vector<klee::ref<klee::Expr>> args(5);
        args[0] = klee::ConstantExpr::create(intno, sizeof(int) * 8);
        args[1] = klee::ConstantExpr::create(is_int, sizeof(int) * 8);
        args[2] = klee::ConstantExpr::create(error_code, sizeof(int) * 8);
        args[3] = klee::ConstantExpr::create(next_eip, sizeof(target_ulong) * 8);
        args[4] = klee::ConstantExpr::create(is_hw, sizeof(int) * 8);
        try {
            if (EnableTimingLog) {
                TimerStatIncrementer t(stats::symbolicModeTime);
            }
            executeFunction(state, "se_do_interrupt_all", args);
        } catch (s2e::CpuExitException &) {
            updateStates(state);
            longjmp(env->jmp_env, 1);
        }
    }
}

/**
 *  We also need to track when execution enters/exits emulation code.
 *  Some plugins do not care about what memory accesses the emulation
 *  code performs internally, therefore, there must be a means for such
 *  plugins to enable/disable tracing upon exiting/entering
 *  the emulation code.
 */
void S2EExecutor::doInterruptAll(int intno, int is_int, int error_code, uintptr_t next_eip, int is_hw) {
    g_s2e_state->setRunningExceptionEmulationCode(true);

    if (unlikely(*g_s2e_on_exception_signals_count))
        s2e_on_exception(intno);

    if (likely(g_s2e_fast_concrete_invocation)) {
        if (unlikely(!g_s2e_state->isRunningConcrete())) {
            s2e::S2EExecutor *executor = g_s2e->getExecutor();
            executor->updateConcreteFastPath(g_s2e_state);
            assert(g_s2e_fast_concrete_invocation);
            executor->switchToConcrete(g_s2e_state);
        }
        se_do_interrupt_all(intno, is_int, error_code, next_eip, is_hw);
    } else {
        g_s2e->getExecutor()->doInterrupt(g_s2e_state, intno, is_int, error_code, next_eip, is_hw);
    }

    g_s2e_state->setRunningExceptionEmulationCode(false);
}

void S2EExecutor::setupTimersHandler() {
    m_s2e->getCorePlugin()->onTimer.connect(sigc::bind(sigc::ptr_fun(&onAlarm), 0));
}

/** Suspend the given state (does not kill it) */
bool S2EExecutor::suspendState(S2EExecutionState *state, bool onlyRemoveFromPtree) {
    if (onlyRemoveFromPtree) {
        processTree->deactivate(state->ptreeNode);
        return true;
    }

    if (searcher) {
        searcher->removeState(state, NULL);
        size_t r = states.erase(state);
        assert(r == 1);
        processTree->deactivate(state->ptreeNode);
        return true;
    }
    return false;
}

bool S2EExecutor::resumeState(S2EExecutionState *state, bool onlyAddToPtree) {
    if (onlyAddToPtree) {
        processTree->activate(state->ptreeNode);
        return true;
    }

    if (searcher) {
        if (states.find(state) != states.end()) {
            return false;
        }
        processTree->activate(state->ptreeNode);
        states.insert(state);
        searcher->addState(state, NULL);
        return true;
    }
    return false;
}

void S2EExecutor::refLLVMTb(llvm::Function *tb) {
    assert(tb);
    m_llvmBlockReferences[tb]++;
}

void S2EExecutor::unrefLLVMTb(llvm::Function *tb) {
    assert(tb);
    LLVMTbReferences::iterator it = m_llvmBlockReferences.find(tb);
    assert(it != m_llvmBlockReferences.end());
    assert((*it).second > 0);

    if (--(*it).second) {
        return;
    }

    m_llvmBlockReferences.erase(it);

    S2EExternalDispatcher *s2eDispatcher = static_cast<S2EExternalDispatcher *>(externalDispatcher);
    s2eDispatcher->removeFunction(tb);

    bool doErase = !KeepLLVMFunctions;
    if (PersistentTbCache.size()) {
        // Keeping instrumented blocks does not make sense for now
        doErase |= m_tcgLLVMContext->isInstrumented(tb);
    }

    if (!doErase) {
        return;
    }

    // We may have generated LLVM code that was never executed
    if (kmodule->functionMap.find(tb) != kmodule->functionMap.end()) {
        kmodule->removeFunction(tb);
    } else {
        tb->eraseFromParent();
    }
}

void S2EExecutor::refS2ETb(S2ETranslationBlock *se_tb) {
    se_tb->refCount++;
    if (se_tb->llvm_function) {
        refLLVMTb(se_tb->llvm_function);
    }
}

void S2EExecutor::unrefS2ETb(S2ETranslationBlock *se_tb) {
    if (!se_tb) {
        return;
    }

    if (--se_tb->refCount) {
        return;
    }

    if (se_tb->llvm_function) {
        unrefLLVMTb(se_tb->llvm_function);
    }

    foreach2 (it, se_tb->executionSignals.begin(), se_tb->executionSignals.end()) {
        delete static_cast<ExecutionSignal *>(*it);
    }

    delete se_tb;
}

void S2EExecutor::updateStats(S2EExecutionState *state) {
    state->m_stats.updateStats(state);
    processTimers(state);
}

void S2EExecutor::updateStates(klee::ExecutionState *current) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(current);
    m_s2e->getCorePlugin()->onUpdateStates.emit(state, addedStates, removedStates);
    klee::Executor::updateStates(current);
}

} // namespace s2e

/*******************************/
/* Functions called by clients */

void s2e_create_initial_state() {
    g_s2e_state = g_s2e->getExecutor()->createInitialState();
}

void s2e_initialize_execution(int execute_always_klee) {
    g_s2e->getExecutor()->initializeExecution(g_s2e_state, execute_always_klee);
    // XXX: move it to better place (signal handler for this?)
    tcg_register_helper((void *) &s2e_tcg_execution_handler, "s2e_tcg_execution_handler");
    tcg_register_helper((void *) &s2e_tcg_custom_instruction_handler, "s2e_tcg_custom_instruction_handler");
}

void s2e_register_cpu(CPUX86State *cpu_env) {
    g_s2e->getExecutor()->registerCpu(g_s2e_state, cpu_env);
}

// TODO: remove unused params
void s2e_register_ram(MemoryDesc *region, uint64_t start_address, uint64_t size, uint64_t host_address,
                      int is_shared_concrete, int save_on_context_switch, const char *name) {
    g_s2e->getExecutor()->registerRam(g_s2e_state, region, start_address, size, host_address, is_shared_concrete,
                                      save_on_context_switch, name);
}

void s2e_register_ram2(const char *name, uint64_t host_address, uint64_t size, int is_shared_concrete) {
    g_s2e->getExecutor()->registerRam(g_s2e_state, NULL, -1, size, host_address, is_shared_concrete, false, name);
}

void s2e_register_dirty_mask(uint64_t host_address, uint64_t size) {
    g_s2e->getExecutor()->registerDirtyMask(g_s2e_state, host_address, size);
}

int s2e_libcpu_finalize_tb_exec() {
    return g_s2e->getExecutor()->finalizeTranslationBlockExec(g_s2e_state);
}

void s2e_libcpu_cleanup_tb_exec() {
    return g_s2e->getExecutor()->cleanupTranslationBlock(g_s2e_state);
}

void s2e_set_cc_op_eflags(struct CPUX86State *env1) {
    env = env1;
    g_s2e->getExecutor()->setCCOpEflags(g_s2e_state);
}

void s2e_switch_to_symbolic(void *retaddr) {
    TranslationBlock *tb = tb_find_pc((uintptr_t) retaddr);
    assert(tb);
    cpu_restore_state(tb, env, (uintptr_t) retaddr);

    // XXX: For now, we assume that symbolic hardware, when triggered,
    // will want to start symbexec.
    g_s2e_state->enableSymbolicExecution();
    g_s2e_state->jumpToSymbolic();
}

void se_ensure_symbolic() {
    g_s2e_state->jumpToSymbolic();
}

void se_tb_alloc(TranslationBlock *tb) {
    S2ETranslationBlock *se_tb = new S2ETranslationBlock;

    se_tb->llvm_function = NULL;
    se_tb->refCount = 1;

    /* Push one copy of a signal to use it as a cache */
    se_tb->executionSignals.push_back(new s2e::ExecutionSignal);

    tb->se_tb_next[0] = 0;
    tb->se_tb_next[1] = 0;

    tb->se_tb = se_tb;
}

int s2e_is_tb_instrumented(TranslationBlock *tb) {
    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    unsigned size = se_tb->executionSignals.size();
    return size > 1;
}

void s2e_set_tb_function(TranslationBlock *tb) {
    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    se_tb->llvm_function = static_cast<Function *>(tb->llvm_function);
    g_s2e->getExecutor()->refLLVMTb(se_tb->llvm_function);
}

void se_tb_free(TranslationBlock *tb) {
    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    g_s2e->getExecutor()->unrefS2ETb(se_tb);
    tb->se_tb = NULL;
}

void s2e_flush_tb_cache() {
    klee::stats::availableTranslationBlocks += -klee::stats::availableTranslationBlocks;
    klee::stats::availableTranslationBlocksInstrumented += -klee::stats::availableTranslationBlocksInstrumented;

    if (g_s2e && g_s2e->getExecutor()->getStatesCount() > 1) {
        if (!FlushTBsOnStateSwitch) {
            g_s2e->getWarningsStream() << "Flushing TB cache with more than 1 state. Dangerous. Expect crashes.\n";
        }
    }
}

void s2e_increment_tb_stats(TranslationBlock *tb) {
    ++klee::stats::availableTranslationBlocks;
    if (tb->instrumented) {
        ++klee::stats::availableTranslationBlocksInstrumented;
    }
}

void s2e_flush_tlb_cache() {
    g_s2e_state->getTlb()->flushTlbCache();
}

void se_flush_tlb_cache_page(void *objectState, int mmu_idx, int index) {
    g_s2e_state->getTlb()->flushTlbCachePage(static_cast<klee::ObjectState *>(objectState), mmu_idx, index);
}

/** Tlb cache helpers */
void s2e_update_tlb_entry(CPUX86State *env, int mmu_idx, uint64_t virtAddr, uint64_t hostAddr) {
#if defined(SE_ENABLE_TLB) && defined(CONFIG_SYMBEX_MP)
    g_s2e_state->getTlb()->updateTlbEntry(env, mmu_idx, virtAddr, hostAddr);
#endif
}

int s2e_is_load_balancing() {
    return g_s2e->getExecutor()->isLoadBalancing();
}

void helper_register_symbol(const char *name, void *address) {
    llvm::sys::DynamicLibrary::AddSymbol(name, address);
}

uint64_t s2e_read_mem_io_vaddr(int masked) {
    return g_s2e_state->readMemIoVaddr(masked);
}

void s2e_kill_state(const char *message) {
    g_s2e->getExecutor()->terminateStateEarly(*g_s2e_state, message);
}

#ifdef S2E_DEBUG_MEMORY
#ifdef __linux__

#include <execinfo.h>
#include <cxxabi.h>

static FILE *s_mallocfp = NULL;

static void init_mem_debug() {
    if (s_mallocfp) {
        return;
    }

    s_mallocfp = fopen("mem.log", "w");
    if (!s_mallocfp) {
        fprintf(stderr, "Could not init malloc trace log\n");
        exit(-1);
    }
}

static void mem_backtrace(const char *type, void *ptr, unsigned sz) {
    unsigned int max_frames = 63;
    void *addrlist[max_frames + 1];

    fprintf(s_mallocfp, "%s a=%p sz=%#x ", type, ptr, sz);

    // retrieve current stack addresses
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void *));

    if (addrlen == 0) {
        return;
    }

    for (int i = 1; i < addrlen; i++) {
        fprintf(s_mallocfp, "%p ", addrlist[i]);
    }

    fprintf(s_mallocfp, "\n");
}

void *operator new(size_t s) throw(std::bad_alloc) {
    init_mem_debug();
    void *ret = malloc(s);
    if (!ret) {
        throw std::bad_alloc();
    }

    memset(ret, 0xAA, s);
    mem_backtrace("A", ret, s);
    return ret;
}

void *operator new[](size_t s) throw(std::bad_alloc) {
    init_mem_debug();
    void *ret = malloc(s);
    if (!ret) {
        throw std::bad_alloc();
    }

    memset(ret, 0xAA, s);
    mem_backtrace("A", ret, s);
    return ret;
}

void operator delete(void *pvMem) throw() {
    init_mem_debug();
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
    mem_backtrace("D", pvMem, s);
}

void operator delete[](void *pvMem) throw() {
    init_mem_debug();
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
    mem_backtrace("D", pvMem, s);
}
#endif

#endif
