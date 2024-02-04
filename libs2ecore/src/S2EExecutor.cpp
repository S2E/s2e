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

#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExternalDispatcher.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/s2e_config.h>

#include <s2e/S2EDeviceState.h>
#include <s2e/S2EStatsTracker.h>

#include <s2e/s2e_libcpu.h>

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

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <llvm/ADT/IntervalMap.h>

#include <klee/ExternalDispatcher.h>
#include <klee/Memory.h>
#include <klee/Searcher.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <klee/Stats/CoreStats.h>
#include <klee/Stats/TimerStatIncrementer.h>
#include <klee/util/ExprTemplates.h>

#include <tcg/tcg-llvm.h>

#include <glib.h>
#include <sstream>
#include <vector>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <functional>

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
    ClockSlowDownConcrete("clock-slow-down-concrete",
            cl::desc("Slow down factor when running concrete code"),
            cl::init(1));

    cl::opt<unsigned>
    ClockSlowDownFastHelpers("clock-slow-down-fast-helpers",
            cl::desc("Slow down factor when interpreting LLVM code and using fast helpers"),
            cl::init(11));

    cl::opt<bool>
    SinglePathMode("single-path-mode",
            cl::desc("Faster TLB, but forces single path execution"),
            cl::init(false));

    cl::opt<bool> NoTruncateSourceLines("no-truncate-source-lines",
                                    cl::desc("Don't truncate long lines in the output source"));

    cl::opt<bool> OutputSource("output-source", cl::desc("Write the assembly for the final transformed source"),
                            cl::init(true));

    cl::opt<bool> OutputModule("output-module", cl::desc("Write the bitcode for the final transformed module"),
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

cl::opt<bool>
DebugConstraints("debug-constraints",
            cl::desc("Check that added constraints are satisfiable"),
            cl::init(false));

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

    char *g_s2e_running_exception_emulation_code = nullptr;

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

S2EExecutor::S2EExecutor(S2E *s2e, TCGLLVMTranslator *translator)
    : Executor(translator->getContext()), m_s2e(s2e), m_llvmTranslator(translator), m_executeAlwaysKlee(false),
      m_forkProcTerminateCurrentState(false), m_inLoadBalancing(false) {
    delete externalDispatcher;
    externalDispatcher = new S2EExternalDispatcher();

    LLVMContext &ctx = m_llvmTranslator->getContext();

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

    __DEFINE_EXT_FUNCTION(exit)
    __DEFINE_EXT_FUNCTION(fprintf)
    __DEFINE_EXT_FUNCTION(sprintf)
    __DEFINE_EXT_FUNCTION(fputc)
    __DEFINE_EXT_FUNCTION(fwrite)
    __DEFINE_EXT_FUNCTION(memset)
    __DEFINE_EXT_FUNCTION(memcpy)
    __DEFINE_EXT_FUNCTION(memmove)

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
    __DEFINE_EXT_FUNCTION(cpu_outb)
    __DEFINE_EXT_FUNCTION(cpu_outw)
    __DEFINE_EXT_FUNCTION(cpu_outl)
    __DEFINE_EXT_FUNCTION(cpu_inb)
    __DEFINE_EXT_FUNCTION(cpu_inw)
    __DEFINE_EXT_FUNCTION(cpu_inl)
    __DEFINE_EXT_FUNCTION(cpu_restore_state)
    __DEFINE_EXT_FUNCTION(cpu_abort)
    __DEFINE_EXT_FUNCTION(cpu_loop_exit)
    __DEFINE_EXT_FUNCTION(cpu_loop_exit_restore)
    __DEFINE_EXT_FUNCTION(cpu_get_tsc)
    __DEFINE_EXT_FUNCTION(cpu_exit)

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
    __DEFINE_EXT_FUNCTION(se_is_vmem_symbolic)

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

    /* This catches obvious LLVM misconfigurations */
    Module *M = m_llvmTranslator->getModule();
    s2e->getDebugStream() << "Current data layout: " << M->getDataLayoutStr() << '\n';
    s2e->getDebugStream() << "Current target triple: " << M->getTargetTriple() << '\n';

    auto &td = M->getDataLayout();

    if (td.getPointerSizeInBits() != 64) {
        s2e->getWarningsStream() << "Something is broken in your LLVM build: LLVM thinks pointers are 32-bits!\n";
        exit(-1);
    }

    setModule(m_llvmTranslator->getModule());

    if (UseFastHelpers) {
        disableConcreteLLVMHelpers();
    }

    /* Add dummy TB function declaration */
    PointerType *tbFunctionArgTy = PointerType::get(IntegerType::get(ctx, 64), 0);
    FunctionType *tbFunctionTy =
        FunctionType::get(IntegerType::get(ctx, TCG_TARGET_REG_BITS),
                          ArrayRef<Type *>(vector<Type *>(1, PointerType::get(IntegerType::get(ctx, 64), 0))), false);

    Function *tbFunction =
        Function::Create(tbFunctionTy, Function::PrivateLinkage, "s2e_dummyTbFunction", m_llvmTranslator->getModule());

    /* Create dummy main function containing just two instructions:
       a call to TB function and ret */
    Function *dummyMain = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false), Function::ExternalLinkage,
                                           "s2e_dummyMainFunction", m_llvmTranslator->getModule());

    BasicBlock *dummyMainBB = BasicBlock::Create(ctx, "entry", dummyMain);

    vector<Value *> tbFunctionArgs(1, ConstantPointerNull::get(tbFunctionArgTy));
    CallInst::Create(tbFunction, ArrayRef<Value *>(tbFunctionArgs), "tbFunctionCall", dummyMainBB);
    ReturnInst::Create(m_llvmTranslator->getContext(), dummyMainBB);

    kmodule->updateModuleWithFunction(dummyMain);
    m_dummyMain = kmodule->getKFunction(dummyMain);

#ifdef CONFIG_SYMBEX_MP
    registerFunctionHandlers(*kmodule->getModule());

    if (UseFastHelpers) {
        replaceExternalFunctionsWithSpecialHandlers();
    }
#endif

    searcher = constructUserSearcher();

    g_s2e_fork_on_symbolic_address = ForkOnSymbolicAddress;
    g_s2e_concretize_io_addresses = ConcretizeIoAddress;
    g_s2e_concretize_io_writes = ConcretizeIoWrites;

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

    if (OutputModule) {
        if (auto os = s2e->openOutputFile("module.bc")) {
            kmodule->outputModule(*os);
        }
    }

    if (OutputSource) {
        if (auto os = s2e->openOutputFile("assembly.ll")) {
            kmodule->outputSource(*os, NoTruncateSourceLines);
        }
    }
}

void S2EExecutor::flushTb() {
    tb_flush(env); // release references to TB functions
}

S2EExecutor::~S2EExecutor() {
}

S2EExecutionState *S2EExecutor::createInitialState() {
    /* Create initial execution state */
    S2EExecutionState *state = new S2EExecutionState(m_dummyMain);

    auto factory = klee::DefaultSolverFactory::create(g_s2e->getOutputDirectory());
    auto endSolver = factory->createEndSolver();
    auto solver = factory->decorateSolver(endSolver);
    state->setSolver(solver);

    state->m_runningConcrete = true;
    state->m_active = true;
    state->setForking(EnableForking);

    states.insert(state);
    addedStates.insert(state);
    updateStates(state);

#define __DEFINE_EXT_OBJECT_RO(name)                                                  \
    {                                                                                 \
        predefinedSymbols.insert(std::make_pair(#name, (void *) &name));              \
        auto op = state->addExternalObject((void *) &name, sizeof(name), true, true); \
        op->setName(#name);                                                           \
    }

#define __DEFINE_EXT_OBJECT_RO_SYMB(name)                                              \
    {                                                                                  \
        predefinedSymbols.insert(std::make_pair(#name, (void *) &name));               \
        auto op = state->addExternalObject((void *) &name, sizeof(name), true, false); \
        op->setName(#name);                                                            \
    }

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

    g_s2e_running_exception_emulation_code = (char *) &state->m_runningExceptionEmulationCode;

    return state;
}

void S2EExecutor::initializeExecution(S2EExecutionState *state, bool executeAlwaysKlee) {
    m_executeAlwaysKlee = executeAlwaysKlee;

    initializeGlobals(*state);
    kmodule->bindModuleConstants(globalAddresses);

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
    auto symbolicRegs = initialState->addExternalObject(cpuEnv, offsetof(CPUX86State, eip),
                                                        /* isReadOnly = */ false,
                                                        /* isSharedConcrete = */ false);

    /* Add the rest of the structure as concrete-only area */
    auto concreteRegs = initialState->addExternalObject(((uint8_t *) cpuEnv) + offsetof(CPUX86State, eip),
                                                        sizeof(CPUX86State) - offsetof(CPUX86State, eip),
                                                        /* isReadOnly = */ false,
                                                        /* isSharedConcrete = */ true);

    initialState->m_registers.initialize(initialState->addressSpace, symbolicRegs, concreteRegs);
    klee::ExecutionState::s_ignoredMergeObjects.insert(initialState->m_registers.getConcreteRegs());
}

void S2EExecutor::registerSharedExternalObject(S2EExecutionState *state, void *address, unsigned size) {
    state->addExternalObject(address, size, false, true);
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

        auto os = initialState->addExternalObject((void *) addr, SE_RAM_OBJECT_SIZE, false, isSharedConcrete);

        os->setMemoryPage(true);

        if (!isSharedConcrete) {
            os->setSplittable(true);
            os->setNotifyOnConcretenessChange(true);
        }

#ifdef S2E_DEBUG_MEMOBJECT_NAME
        std::stringstream ss;
        ss << name << "_" << std::hex << (addr - hostAddress);
        mo->setName(ss.str());
#endif

        if (isSharedConcrete && (saveOnContextSwitch || !StateSharedMemory)) {
            m_saveOnContextSwitch.push_back(os->getKey());
        }
    }

    if (!isSharedConcrete) {
        // mprotecting does not actually free the RAM, it's still committed,
        // we need to explicitely unmap it.
        // mprotect((void*) hostAddress, size, PROT_NONE);
        if (munmap((void *) hostAddress, size) < 0) {
            m_s2e->getWarningsStream(nullptr) << "Could not unmap host RAM\n";
            exit(-1);
        }

        // Make sure that the memory space is reserved and won't be used anymore
        // so that there are no conflicts with klee memory objects.
        void *newhost = mmap((void *) hostAddress, size, PROT_NONE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        if (newhost == MAP_FAILED || newhost != (void *) hostAddress) {
            m_s2e->getWarningsStream(nullptr) << "Could not map host RAM\n";
            exit(-1);
        }
    }

    initialState->m_asCache.registerPool(hostAddress, size);
#endif
}

void S2EExecutor::registerDirtyMask(S2EExecutionState *state, uint64_t hostAddress, uint64_t size) {
    // Assume that dirty mask is small enough, so no need to split it in small pages
    auto dirtyMask = state->addExternalObject((void *) hostAddress, size, false, true);

    state->m_memory.initialize(&state->addressSpace, &state->m_asCache, &state->m_active, state, state, dirtyMask);

    klee::ExecutionState::s_ignoredMergeObjects.insert(state->m_memory.getDirtyMask());

    g_se_dirty_mask_addend = state->mem()->getDirtyMaskStoreAddend();
}

void S2EExecutor::splitStates(const std::vector<S2EExecutionState *> &allStates, StateSet &parentSet,
                              StateSet &childSet) {
    unsigned size = allStates.size();
    unsigned n = size / 2;

    for (unsigned i = 0; i < n; ++i) {
        parentSet.insert(allStates[i]);
    }

    for (unsigned i = n; i < allStates.size(); ++i) {
        childSet.insert(allStates[i]);
    }
}

void S2EExecutor::computeNewStateGuids(std::unordered_map<ExecutionState *, uint64_t> &newIds, StateSet &parentSet,
                                       StateSet &childSet) {
    StateSet commonStates;

    // If we there are states that appear in both sets, we must
    // reassign a guid to them.
    std::set_intersection(parentSet.begin(), parentSet.end(), childSet.begin(), childSet.end(),
                          std::inserter(commonStates, commonStates.begin()));

    for (auto state : commonStates) {
        // TODO: if fork fails, we'll end up with unused state ids...
        // It doesn't matter in practice, but may be unintuitive
        // (i.e., why do I have missing state ids in my trace?)
        // Reverting this increment is hard unfortunately.
        newIds[state] = g_s2e->fetchAndIncrementStateId();
    }
}

void S2EExecutor::doLoadBalancing() {
    if (states.size() < 2) {
        return;
    }

    // Don't bother copying stuff if it's obvious that it'll very likely fail
    if (m_s2e->getCurrentInstanceCount() == m_s2e->getMaxInstances()) {
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

    g_s2e->getDebugStream() << "LoadBalancing: starting\n";

    bool proceed = true;
    m_s2e->getCorePlugin()->onProcessForkDecide.emit(&proceed);
    if (!proceed) {
        g_s2e->getDebugStream() << "LoadBalancing: a plugin stopped load balancing\n";
        return;
    }

    // These two sets are the two partitions.
    StateSet parentSet, childSet;

    // Do the splitting before the fork, because we want to
    // let plugins modify the partition. Some plugins might
    // even want to keep a state in all instances.
    splitStates(allStates, parentSet, childSet);

    m_s2e->getCorePlugin()->onStatesSplit.emit(parentSet, childSet);

    std::unordered_map<ExecutionState *, uint64_t> newIds;
    computeNewStateGuids(newIds, parentSet, childSet);

    m_inLoadBalancing = true;

    unsigned parentId = m_s2e->getCurrentInstanceId();
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
            Executor::terminateState(*s2estate);

            // This is important if we kill the current state
            s2estate->zombify();
        }
    }

    // We have to re-assign globally unique IDs to states that
    // have been kept in both child and parent sets. This is required
    // to avoid confusing execution tracers.
    for (auto &state : newIds) {
        S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state.first);
        if (child) {
            g_s2e->getDebugStream(s2estate) << "Assigning new guid " << state.second << "\n";
            s2estate->assignGuid(state.second);
        } else {
            g_s2e->getDebugStream(s2estate) << "Notifying guid assignment " << state.second << "\n";
            m_s2e->getCorePlugin()->onStateGuidAssignment.emit(s2estate, state.second);
        }
    }

    m_s2e->getCorePlugin()->onProcessForkComplete.emit(child);

    m_inLoadBalancing = false;
}

void S2EExecutor::stateSwitchTimerCallback(void *opaque) {
    S2EExecutor *c = (S2EExecutor *) opaque;

    assert(env->current_tb == nullptr);

    if (g_s2e_state) {
        c->doLoadBalancing();
        S2EExecutionState *nextState = c->selectNextState(g_s2e_state);
        if (nextState) {
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
    assert(!newState || !newState->isRunningConcrete());

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

        if (oldState->isRunningConcrete()) {
            oldState->switchToSymbolic();
        }

        for (auto &mo : m_saveOnContextSwitch) {
            auto oldOS = oldState->addressSpace.findObject(mo.address);
            auto oldWOS = oldState->addressSpace.getWriteable(oldOS);
            uint8_t *oldStore = oldWOS->getConcreteBuffer();
            assert(oldStore);
            memcpy(oldStore, (uint8_t *) mo.address, mo.size);
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
        if (g_sqi.exec.clock_scaling_factor) {
            *g_sqi.exec.clock_scaling_factor = timers_state.cpu_clock_scale_factor;
        }

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

        for (auto &mo : m_saveOnContextSwitch) {
            auto newOS = newState->addressSpace.findObject(mo.address);
            const uint8_t *newStore = newOS->getConcreteBuffer();
            assert(newStore);
            memcpy((uint8_t *) mo.address, newStore, mo.size);
            totalCopied += mo.size;
            objectsCopied++;
        }
    }

    cpu_enable_ticks();

    if (VerboseStateSwitching) {
        s2e_debug_print("Copied %d (count=%d)\n", totalCopied, objectsCopied);
    }

    if (FlushTBsOnStateSwitch) {
        se_tb_safe_flush();
    }

    assert(env->current_tb == nullptr);

    g_se_disable_tlb_flush = 0;

    // m_s2e->getCorePlugin()->onStateSwitch.emit(oldState, newState);
}

ExecutionState *S2EExecutor::selectSearcherState(S2EExecutionState *state) {
    ExecutionState *newState = nullptr;

    if (!searcher->empty()) {
        newState = &searcher->selectState();
    }

    if (!newState) {
        m_s2e->getWarningsStream() << "All states were terminated" << '\n';
        foreach2 (it, m_deletedStates.begin(), m_deletedStates.end()) {
            S2EExecutionState *s = *it;
            // Leave the current state in a zombie form to let the process exit gracefully.
            if (s != g_s2e_state) {
                delete s;
            }
        }
        m_deletedStates.clear();
        g_s2e->getCorePlugin()->onEngineShutdown.emit();

        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
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
    if (nstate == nullptr) {
        return nullptr;
    }

    // This assertion must go before the cast to S2EExecutionState.
    // In case the searcher returns a bogus state, this allows
    // spotting it immediately. The dynamic cast however, might cause
    // memory corruptions.
    assert(states.find(nstate) != states.end());

    S2EExecutionState *newState = dynamic_cast<S2EExecutionState *>(nstate);

    assert(newState);

    assert(!newState->isZombie());

    newState->setYieldState(false);

    if (!state->m_active) {
        /* Current state might be switched off by merge method */
        state = nullptr;
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
        delete s;
    }
    m_deletedStates.clear();

    updateConcreteFastPath(newState);

    return newState;
}

/** Simulate start of function execution, creating KLEE structs of required */
void S2EExecutor::prepareFunctionExecution(S2EExecutionState *state, llvm::Function *function,
                                           const std::vector<klee::ref<klee::Expr>> &args) {
    auto kf = kmodule->bindFunctionConstants(globalAddresses, function);

    /* Emulate call to a TB function */
    state->prevPC = state->pc;

    state->pushFrame(state->pc, kf);
    state->pc = kf->getInstructions();

    /* Pass argument */
    for (unsigned i = 0; i < args.size(); ++i) {
        state->bindArgument(kf, i, args[i]);
    }
}

inline bool S2EExecutor::executeInstructions(S2EExecutionState *state, unsigned callerStackSize) {
    try {
        while (state->stack.size() != callerStackSize) {
            assert(!g_s2e_fast_concrete_invocation);

            KInstruction *ki = state->pc;

            if (PrintLLVMInstructions) {
                m_s2e->getDebugStream(state)
                    << "executing " << ki->inst->getParent()->getParent()->getName().str() << ": " << *ki->inst << '\n';
            }

            state->stepInstruction();
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
        state->pc = m_dummyMain->getInstructions();
    }

    return false;
}

bool S2EExecutor::finalizeTranslationBlockExec(S2EExecutionState *state) {
    if (!state->m_needFinalizeTBExec)
        return false;

    state->m_needFinalizeTBExec = false;
    state->m_forkAborted = false;

    assert(state->stack.size() != 1);

    assert(!state->isRunningConcrete());

    if (VerboseTbFinalize) {
        m_s2e->getDebugStream(state) << "Finalizing TB execution\n";
        for (const auto &fr : state->stack) {
            m_s2e->getDebugStream() << fr.kf->getFunction()->getName().str() << '\n';
        }
    }

    /**
     * TBs can fork anywhere and the remainder can also throw exceptions.
     * Should exit the CPU loop in this case.
     */
    bool ret = executeInstructions(state);

    if (VerboseTbFinalize) {
        m_s2e->getDebugStream(state) << "Done finalizing TB execution, new pc=" << hexval(state->regs()->getPc())
                                     << "\n";
    }

    /**
     * Memory topology may change on state switches.
     * Ensure that there are no bad mappings left.
     */
    tlb_flush(env, 1);

    return ret;
}

void S2EExecutor::updateClockScaling() {
    int scaling = ClockSlowDownConcrete;

    if (g_s2e_fast_concrete_invocation) {
        // Concrete execution
        scaling = timers_state.cpu_clock_scale_factor / 2;
        if (scaling == 0) {
            scaling = ClockSlowDownConcrete;
        }
    } else {
        // Symbolic execution
        scaling = UseFastHelpers ? ClockSlowDownFastHelpers : ClockSlowDown;
    }

    if (g_sqi.exec.clock_scaling_factor) {
        *g_sqi.exec.clock_scaling_factor = scaling;
    }

    cpu_enable_scaling(scaling);
}

void S2EExecutor::updateConcreteFastPath(S2EExecutionState *state) {
    bool allConcrete = state->regs()->allConcrete();
    g_s2e_fast_concrete_invocation = (allConcrete) && (state->m_toRunSymbolically.size() == 0) &&
                                     (state->m_startSymbexAtPC == (uint64_t) -1) &&

                                     // Check that we are not currently running in KLEE
                                     //(CPU register access from concrete code depend on g_s2e_fast_concrete_invocation)
                                     (state->stack.size() == 1) &&

                                     (m_executeAlwaysKlee == false) && (state->isRunningConcrete());

    g_s2e_running_exception_emulation_code = (char *) &state->m_runningExceptionEmulationCode;

    if (g_s2e_fast_concrete_invocation) {
        env->generate_llvm = 0;
    }

    updateClockScaling();
}

uintptr_t S2EExecutor::executeTranslationBlockKlee(S2EExecutionState *state, TranslationBlock *tb) {
    assert(state->m_active && !state->isRunningConcrete());
    assert(state->stack.size() == 1);
    assert(state->pc == m_dummyMain->getInstructions());

    if (!tb->llvm_function) {
        abort();
    }

    state->m_lastS2ETb = S2ETranslationBlockPtr(static_cast<S2ETranslationBlock *>(tb->se_tb));

    /* Prepare function execution */
    std::vector<klee::ref<Expr>> args;
    args.push_back(klee::ConstantExpr::create((uint64_t) env, Expr::Int64));

    prepareFunctionExecution(state, static_cast<Function *>(tb->llvm_function), args);

    if (executeInstructions(state)) {
        throw CpuExitException();
    }

    state->m_lastS2ETb = nullptr;

    // XXX: TBs may be reused, persisted, etc.
    // The returned value stored has no meaning (could refer to
    // flushed TBs, etc.).
    return 0;
}

uintptr_t S2EExecutor::executeTranslationBlockConcrete(S2EExecutionState *state, TranslationBlock *tb) {
    assert(state->isActive() && state->isRunningConcrete());

    uintptr_t ret = 0;
    S2EExternalDispatcher::saveJmpBuf();

    if (setjmp(env->jmp_env)) {
        S2EExternalDispatcher::restoreJmpBuf();
        throw CpuExitException();
    } else {
        ret = tcg_qemu_tb_exec(env, tb->tc.ptr);
    }

    S2EExternalDispatcher::restoreJmpBuf();
    return ret;
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
            g_s2e_state->switchToConcrete();
        }
        return tcg_qemu_tb_exec(env, tb->tc.ptr);
    } else {
        return executeTranslationBlockSlow(env, tb);
    }
}

uintptr_t S2EExecutor::executeTranslationBlock(S2EExecutionState *state, TranslationBlock *tb) {
    assert(state->isActive());

    updateConcreteFastPath(state);

    bool executeKlee = m_executeAlwaysKlee;

    if (state->m_startSymbexAtPC != (uint64_t) -1) {
        executeKlee |= (state->regs()->getPc() == state->m_startSymbexAtPC);

        if (executeKlee && !tb->llvm_function) {
            env->generate_llvm = 1;
            return 0;
        }

        state->m_startSymbexAtPC = (uint64_t) -1;
    }

    // XXX: hack to run code symbolically that may be delayed because of interrupts.
    // Size check is important to avoid expensive calls to getPc/getPid in the common case
    if (state->m_toRunSymbolically.size() > 0) {
        auto pair = std::make_pair(state->regs()->getPc(), state->regs()->getPageDir());
        if (state->m_toRunSymbolically.find(pair) != state->m_toRunSymbolically.end()) {
            if (!tb->llvm_function) {
                env->generate_llvm = 1;
                return 0;
            }
            state->m_toRunSymbolically.erase(pair);
        }
    }

    // If the CPU state has symbolic registers, run in KLEE.
    // In theory, we could check which registers are symbolic and decide whether
    // the TB should be ran symbolically if it accesses symbolic registers.
    // In practice, the implementation complexity of this check is just too high
    // and it doesn't give a lot of speedup anyway.
    auto allConcrete = state->regs()->allConcrete();
    if (!allConcrete) {
        executeKlee = true;
    }

    if (executeKlee && !tb->llvm_function) {
        env->generate_llvm = 1;
        return 0;
    }

    if (executeKlee) {
        if (state->isRunningConcrete()) {
            state->switchToSymbolic();
        }

        return executeTranslationBlockKlee(state, tb);
    } else {
        env->generate_llvm = 0;

        if (!state->isRunningConcrete()) {
            state->switchToConcrete();
        }

        return executeTranslationBlockConcrete(state, tb);
    }
}

void S2EExecutor::cleanupTranslationBlock(S2EExecutionState *state) {
    assert(state->m_active);

    if (state->m_forkAborted) {
        return;
    }

    while (state->stack.size() != 1) {
        state->popFrame();
    }

    state->prevPC = 0;
    state->pc = m_dummyMain->getInstructions();
}

klee::ref<klee::Expr> S2EExecutor::executeFunction(S2EExecutionState *state, llvm::Function *function,
                                                   const std::vector<klee::ref<klee::Expr>> &args) {
    assert(!state->isRunningConcrete());
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

    if (callerPC == m_dummyMain->getInstructions()) {
        assert(state->stack.size() == 1);
        state->prevPC = 0;
        state->pc = callerPC;
    }

    klee::ref<Expr> resExpr(0);
    if (function->getReturnType()->getTypeID() != Type::VoidTyID) {
        resExpr = state->getDestCell(state->pc).value;
    }

    return resExpr;
}

klee::ref<klee::Expr> S2EExecutor::executeFunction(S2EExecutionState *state, const std::string &functionName,
                                                   const std::vector<klee::ref<klee::Expr>> &args) {
    auto function = kmodule->getModule()->getFunction(functionName);
    assert(function && "function with given name do not exists in LLVM module");
    return executeFunction(state, function, args);
}

void S2EExecutor::deleteState(klee::ExecutionState *state) {
    assert(dynamic_cast<S2EExecutionState *>(state));
    m_deletedStates.push_back(static_cast<S2EExecutionState *>(state));
}

void S2EExecutor::notifyFork(ExecutionState &originalState, klee::ref<Expr> &condition, Executor::StatePair &targets) {
    if (targets.first == nullptr || targets.second == nullptr) {
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

Executor::StatePair S2EExecutor::forkAndConcretize(S2EExecutionState *state, klee::ref<Expr> &value_) {
    assert(!state->isRunningConcrete());

    klee::ref<klee::Expr> value = value_;
    klee::ref<klee::ConstantExpr> concreteValue = state->toConstantSilent(value);

    klee::ref<klee::Expr> condition = EqExpr::create(concreteValue, value);
    Executor::StatePair sp = fork(*state, condition);

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

S2EExecutor::StatePair S2EExecutor::fork(ExecutionState &current, const klee::ref<Expr> &condition,
                                         bool keepConditionTrueInCurrentState) {
    return doFork(current, condition, keepConditionTrueInCurrentState);
}

S2EExecutor::StatePair S2EExecutor::fork(ExecutionState &current) {
    return doFork(current, nullptr, false);
}

S2EExecutor::StatePair S2EExecutor::doFork(ExecutionState &current, const klee::ref<Expr> &condition,
                                           bool keepConditionTrueInCurrentState) {
    S2EExecutionState *currentState = dynamic_cast<S2EExecutionState *>(&current);
    assert(currentState);
    assert(!currentState->isRunningConcrete());

    StatePair res;

    // Check if we should fork the current state.
    // 1. If no conditions are passed to us, then the user wants to explicitly
    //    fork the current state, and thus we should perform the check.
    // 2. If the condition is constant, there is no need to do anything
    //    as the fork will not branch.
    bool forkOk = true;
    if (!condition || !dyn_cast<klee::ConstantExpr>(condition)) {
        if (currentState->forkDisabled) {
            g_s2e->getDebugStream(currentState) << "fork disabled at " << hexval(currentState->regs()->getPc()) << "\n";
        }

        g_s2e->getCorePlugin()->onStateForkDecide.emit(currentState, condition, forkOk);
        if (!forkOk) {
            g_s2e->getDebugStream(currentState) << "fork prevented by request from plugin\n";
        }
    }

    bool oldForkStatus = currentState->forkDisabled;
    if (!forkOk && !currentState->forkDisabled) {
        currentState->forkDisabled = true;
    }

    if (condition) {
        res = Executor::fork(current, condition, keepConditionTrueInCurrentState);
    } else {
        res = Executor::fork(current);
    }

    currentState->forkDisabled = oldForkStatus;

    if (!(res.first && res.second)) {
        return res;
    }

    llvm::SmallVector<S2EExecutionState *, 2> newStates(2);
    llvm::SmallVector<klee::ref<Expr>, 2> newConditions(2);

    newStates[0] = static_cast<S2EExecutionState *>(res.first);
    newStates[1] = static_cast<S2EExecutionState *>(res.second);

    if (condition) {
        newConditions[0] = condition;
        newConditions[1] = klee::NotExpr::create(condition);
    }

    llvm::raw_ostream &out = m_s2e->getInfoStream(currentState);
    out << "Forking state " << currentState->getID() << " at pc = " << hexval(currentState->regs()->getPc())
        << " at pagedir = " << hexval(currentState->regs()->getPageDir()) << '\n';

    for (unsigned i = 0; i < 2; ++i) {
        if (newStates[i]) {
            out << "    state " << newStates[i]->getID();
            if (VerboseFork && condition) {
                out << " with condition " << newConditions[i];
            }
            out << '\n';
        }

        // Handled in ::branch
        if (newStates[i] != currentState) {
            newStates[i]->m_needFinalizeTBExec = true;
            newStates[i]->m_active = false;
        }
    }

    if (VerboseFork) {
        std::stringstream ss;
        currentState->printStack(ss);
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
    S2EExecutor::StatePair sp = fork(*state, condition, keepConditionTrueInCurrentState);
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
/// State pointer will be nullptr when forked state is infeasible.
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

        StatePair sp = fork(*state, condition);
        notifyFork(*state, condition, sp);

        ret.push_back(sp.second);

        if (!sp.first) {
            // expr always equals value, no point in trying other values
            foreach2 (it2, it + 1, values.end()) {
                ret.push_back(nullptr);
            }
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
    for (auto &mo : m_saveOnContextSwitch) {
        auto os = s2eState->addressSpace.findObject(mo.address);
        auto wos = s2eState->addressSpace.getWriteable(os);
        uint8_t *store = wos->getConcreteBuffer();
        assert(store);
        memcpy(store, (uint8_t *) mo.address, mo.size);
    }

#if defined(SE_ENABLE_PHYSRAM_TLB)
    s2eState->m_tlb.clearRamTlb();
#endif

    // We must not save the current tb, because this pointer will become
    // stale on state restore. If a signal occurs while restoring the state,
    // its handler will try to unlink a stale tb, which could cause a hang
    // or a crash.
    auto old_tb = env->current_tb;
    env->current_tb = nullptr;
    s2eState->m_registers.saveConcreteState();
    env->current_tb = old_tb;

    cpu_disable_ticks();
    s2e_kvm_save_device_state();
    *s2eState->m_timersState = timers_state;
    cpu_enable_ticks();
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
        doStateSwitch(&base, nullptr);
    }

    if (other.m_active) {
        s2 = true;
        doStateSwitch(&other, nullptr);
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
        doStateSwitch(nullptr, &base);
    }

    if (s2) {
        doStateSwitch(nullptr, &other);
    }

    if (result) {
        g_s2e->getCorePlugin()->onStateMerge.emit(&base, &other);
    }

    return result;
}

void S2EExecutor::terminateState(klee::ExecutionState &state, const std::string &message) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(&state);
    m_s2e->getInfoStream(s2estate) << "Terminating state: " << message << "\n";
    terminateState(state);
}

void S2EExecutor::terminateState(ExecutionState &s) {
    S2EExecutionState &state = static_cast<S2EExecutionState &>(s);

    m_s2e->getCorePlugin()->onStateKill.emit(&state);

    Executor::terminateState(state);
    state.zombify();

    g_s2e->getWarningsStream().flush();
    g_s2e->getDebugStream().flush();

    // No need for exiting the loop if we kill another state.
    if (!m_inLoadBalancing && (&state == g_s2e_state)) {
        state.regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
        throw CpuExitException();
    }
}

inline void S2EExecutor::setCCOpEflags(S2EExecutionState *state) {
    uint32_t cc_op = 0;

    // Check wether any of cc_op, cc_src, cc_dst or cc_tmp are symbolic
    if (state->m_registers.flagsRegistersAreSymbolic() || m_executeAlwaysKlee) {
        // call set_cc_op_eflags only if cc_op is symbolic or cc_op != CC_OP_EFLAGS
        bool ok = state->regs()->read(CPU_OFFSET(cc_op), &cc_op, sizeof(cc_op), false);
        if (!ok || cc_op != CC_OP_EFLAGS) {
            try {
                if (state->isRunningConcrete()) {
                    state->switchToSymbolic();
                }

                executeFunction(state, "helper_set_cc_op_eflags");
            } catch (s2e::CpuExitException &) {
                updateStates(state);
                longjmp(env->jmp_env, 1);
            }
        }
    } else {
        bool ok = state->regs()->read(CPU_OFFSET(cc_op), &cc_op, sizeof(cc_op), false);
        assert(ok);
        if (cc_op != CC_OP_EFLAGS) {
            if (!state->isRunningConcrete()) {
                state->switchToConcrete();
            }
            helper_set_cc_op_eflags();
        }
    }
}

inline void S2EExecutor::doInterrupt(S2EExecutionState *state, int intno, int is_int, int error_code, uint64_t next_eip,
                                     int is_hw) {
    if (state->m_registers.allConcrete() && !m_executeAlwaysKlee) {
        if (!state->isRunningConcrete()) {
            state->switchToConcrete();
        }
        se_do_interrupt_all(intno, is_int, error_code, next_eip, is_hw);
    } else {
        if (state->isRunningConcrete()) {
            state->switchToSymbolic();
        }
        std::vector<klee::ref<klee::Expr>> args(5);
        args[0] = klee::ConstantExpr::create(intno, sizeof(int) * 8);
        args[1] = klee::ConstantExpr::create(is_int, sizeof(int) * 8);
        args[2] = klee::ConstantExpr::create(error_code, sizeof(int) * 8);
        args[3] = klee::ConstantExpr::create(next_eip, sizeof(target_ulong) * 8);
        args[4] = klee::ConstantExpr::create(is_hw, sizeof(int) * 8);
        try {
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
            g_s2e_state->switchToConcrete();
        }
        se_do_interrupt_all(intno, is_int, error_code, next_eip, is_hw);
    } else {
        g_s2e->getExecutor()->doInterrupt(g_s2e_state, intno, is_int, error_code, next_eip, is_hw);
    }

    g_s2e_state->setRunningExceptionEmulationCode(false);
}

/** Suspend the given state (does not kill it) */
bool S2EExecutor::suspendState(S2EExecutionState *state) {
    if (searcher) {
        searcher->removeState(state, nullptr);
        size_t r = states.erase(state);
        assert(r == 1);
        return true;
    }
    return false;
}

bool S2EExecutor::resumeState(S2EExecutionState *state) {
    if (searcher) {
        if (states.find(state) != states.end()) {
            return false;
        }
        states.insert(state);
        searcher->addState(state, nullptr);
        return true;
    }
    return false;
}

S2ETranslationBlock *S2EExecutor::allocateS2ETb() {
    S2ETranslationBlockPtr se_tb(new S2ETranslationBlock);
    m_s2eTbs.insert(se_tb);
    *klee::stats::translatedBlocksCount += 1;
    return se_tb.get();
}

void S2EExecutor::flushS2ETBs() {
    m_s2eTbs.clear();
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
    g_s2e->getExecutor()->registerRam(g_s2e_state, nullptr, -1, size, host_address, is_shared_concrete, false, name);
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
    cpu_restore_state(env, (uintptr_t) retaddr);
    g_s2e_state->jumpToSymbolic();
}

void se_ensure_symbolic() {
    g_s2e_state->jumpToSymbolic();
}

int se_is_vmem_symbolic(uint64_t vmem, unsigned size) {
    return g_s2e_state->mem()->symbolic(vmem, size);
}

void *se_tb_alloc(void) {
    return g_s2e->getExecutor()->allocateS2ETb();
}

int s2e_is_tb_instrumented(void *se_tb) {
    auto tb = static_cast<S2ETranslationBlock *>(se_tb);
    return tb->executionSignals.size() > 1;
}

// XXX: this assumes that libcpu never deletes generated LLVM functions
void s2e_set_tb_function(void *se_tb, void *llvmFunction) {
    auto tb = static_cast<S2ETranslationBlock *>(se_tb);
    tb->translationBlock = static_cast<llvm::Function *>(llvmFunction);
    *klee::stats::translatedBlocksLLVMCount += 1;
}

void s2e_flush_tb_cache() {
    if (g_s2e && g_s2e->getExecutor()->getStatesCount() > 1) {
        if (!FlushTBsOnStateSwitch) {
            g_s2e->getWarningsStream() << "Flushing TB cache with more than 1 state. Dangerous. Expect crashes.\n";
        }
    }

    g_s2e->getExecutor()->flushS2ETBs();
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
    g_s2e->getExecutor()->terminateState(*g_s2e_state, message);
}

void s2e_print_instructions(bool val) {
    PrintLLVMInstructions = val;
}
