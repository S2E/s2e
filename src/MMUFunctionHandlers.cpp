///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/s2e_libcpu.h>

#include <llvm/IR/Module.h>

using namespace klee;

namespace s2e {

#define S2E_RAM_OBJECT_DIFF (TARGET_PAGE_BITS - SE_RAM_OBJECT_BITS)
#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE 2
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE 0
#define ADDR_READ addr_read
#endif

// XXX: Fix this
#define CPU_MMU_INDEX 0

// This is an io_write_chkX_mmu function
// XXX: width is redundant
static void io_write_chk(S2EExecutionState *state, target_phys_addr_t physaddr, ref<Expr> val, target_ulong addr,
                         void *retaddr, Expr::Width width) {
    // Not implemented yet
    abort();
}

// This is an io_read_chkX_mmu function
static ref<Expr> io_read_chk(S2EExecutionState *state, target_phys_addr_t physaddr, target_ulong addr, void *retaddr,
                             Expr::Width width) {
    // Not implemented yet
    abort();
}

void S2EExecutor::handle_ldb_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    assert(args.size() == 2);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 1, false, false);
    assert(value->getWidth() == Expr::Int8);
    s2eExecutor->bindLocal(target, *state, value);
}

void S2EExecutor::handle_ldw_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    assert(args.size() == 2);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 2, false, false);
    assert(value->getWidth() == Expr::Int16);
    s2eExecutor->bindLocal(target, *state, value);
}

void S2EExecutor::handle_ldl_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    assert(args.size() == 2);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 4, false, false);
    assert(value->getWidth() == Expr::Int32);
    s2eExecutor->bindLocal(target, *state, value);
}

void S2EExecutor::handle_ldq_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    assert(args.size() == 2);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 8, false, false);
    assert(value->getWidth() == Expr::Int64);
    s2eExecutor->bindLocal(target, *state, value);
}

void S2EExecutor::handle_stb_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_mmu(executor, state, target, args, true, 1, false, false);
}

void S2EExecutor::handle_stw_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_mmu(executor, state, target, args, true, 2, false, false);
}

void S2EExecutor::handle_stl_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_mmu(executor, state, target, args, true, 4, false, false);
}

void S2EExecutor::handle_stq_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                 std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_mmu(executor, state, target, args, true, 8, false, false);
}

ref<ConstantExpr> S2EExecutor::handleForkAndConcretizeNative(Executor *executor, ExecutionState *state,
                                                             klee::KInstruction *target, std::vector<ref<Expr>> &args) {
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    ref<Expr> symbAddress = args[0];
    ref<ConstantExpr> constantAddress = dyn_cast<ConstantExpr>(symbAddress);
    if (constantAddress.isNull()) {
        // Find the LLVM instruction that computes the address
        const llvm::Instruction *addrInst = dyn_cast<llvm::Instruction>(target->inst->getOperand(0));
        assert(target->owner->instrMap.count(addrInst));

        std::vector<ref<Expr>> forkArgs;
        forkArgs.push_back(symbAddress);
        forkArgs.push_back(ref<Expr>(NULL));
        forkArgs.push_back(ref<Expr>(NULL));
        forkArgs.push_back(0);
        KInstruction *kinst = (*target->owner->instrMap.find(addrInst)).second;
        S2EExecutor::handleForkAndConcretize(executor, state, kinst, forkArgs);

        constantAddress = dyn_cast<ConstantExpr>(s2eExecutor->getDestCell(*state, kinst).value);
        assert(!constantAddress.isNull());
    }
    return constantAddress;
}

/* Replacement for __ldl_mmu / __stl_mmu */
/* Params: ldl: addr, mmu_idx */
/* Params: stl: addr, val, mmu_idx */
ref<Expr> S2EExecutor::handle_ldst_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                       std::vector<ref<Expr>> &args, bool isWrite, unsigned data_size, bool signExtend,
                                       bool zeroExtend) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);

    ref<Expr> symbAddress = args[0];
    ref<Expr> mmuIdxExpr = args[isWrite ? 2 : 1];
    unsigned mmu_idx = dyn_cast<ConstantExpr>(mmuIdxExpr)->getZExtValue();

    ref<ConstantExpr> constantAddress = handleForkAndConcretizeNative(executor, state, target, args);

    // XXX: determine this by looking at the instruction that called us
    Expr::Width width = data_size * 8;
    Expr::Width addressWidth = symbAddress->getWidth();

    target_ulong addr = constantAddress->getZExtValue();
    target_ulong object_index, index;
    ref<Expr> value;
    target_ulong tlb_addr, addr1, addr2;
    target_phys_addr_t addend, ioaddr;
    void *retaddr = NULL;

    if (isWrite) {
        value = args[1];
        assert(value->getWidth() == width);
    }

    object_index = addr >> SE_RAM_OBJECT_BITS;
    index = (object_index >> S2E_RAM_OBJECT_DIFF) & (CPU_TLB_SIZE - 1);

redo:

    if (isWrite) {
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    } else {
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

    if (likely((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK)))) {
        if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
            /* IO access */
            if ((addr & (data_size - 1)) != 0)
                goto do_unaligned_access;

            ioaddr = env->iotlb[mmu_idx][index];

            if (!isWrite)
                value = io_read_chk(s2estate, ioaddr, addr, retaddr, width);

            // Trace the access
            std::vector<ref<Expr>> traceArgs;
            traceArgs.push_back(symbAddress);
            traceArgs.push_back(value);
            traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
            unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
            traceArgs.push_back(ConstantExpr::create(flags | MEM_TRACE_FLAG_IO, Expr::Int64));
            traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
            handlerAfterMemoryAccess(executor, state, target, traceArgs);

            if (isWrite)
                io_write_chk(s2estate, ioaddr, value, addr, retaddr, width);

        } else if (unlikely(((addr & ~SE_RAM_OBJECT_MASK) + data_size - 1) >= SE_RAM_OBJECT_SIZE)) {
        /* slow unaligned access (it spans two pages or IO) */
        do_unaligned_access:

            if (isWrite) {
                for (int i = data_size - 1; i >= 0; i--) {
                    std::vector<ref<Expr>> unalignedAccessArgs;
#ifdef TARGET_WORDS_BIGENDIAN
                    ref<Expr> shiftCount = ConstantExpr::create((((data_size - 1) * 8) - (i * 8)), width);
#else
                    ref<Expr> shiftCount = ConstantExpr::create(i * 8, width);
#endif

                    ref<Expr> shiftedValue = LShrExpr::create(value, shiftCount);
                    ref<Expr> resizedValue = ExtractExpr::create(shiftedValue, 0, Expr::Int8);
                    unalignedAccessArgs.push_back(ConstantExpr::create(addr + i, addressWidth));
                    unalignedAccessArgs.push_back(resizedValue);
                    unalignedAccessArgs.push_back(mmuIdxExpr);
                    handle_ldst_mmu(executor, state, target, unalignedAccessArgs, true, 1, false, false);
                }
            } else {
                addr1 = addr & ~((target_ulong) data_size - 1);
                addr2 = addr1 + (target_ulong) data_size;

                std::vector<ref<Expr>> unalignedAccessArgs;
                unalignedAccessArgs.push_back(ConstantExpr::create(addr1, addressWidth));
                unalignedAccessArgs.push_back(mmuIdxExpr);
                ref<Expr> value1 = handle_ldst_mmu(executor, state, target, unalignedAccessArgs, isWrite, data_size,
                                                   signExtend, zeroExtend);

                unalignedAccessArgs[0] = ConstantExpr::create(addr2, addressWidth);
                ref<Expr> value2 = handle_ldst_mmu(executor, state, target, unalignedAccessArgs, isWrite, data_size,
                                                   signExtend, zeroExtend);

                ref<Expr> shift = ConstantExpr::create((addr & (data_size - 1)) * 8, width);
                ref<Expr> shift2 = ConstantExpr::create((data_size * 8) - ((addr & (data_size - 1)) * 8), width);

#ifdef TARGET_WORDS_BIGENDIAN
                value = OrExpr::create(ShlExpr::create(value1, shift), LShrExpr::create(value2, shift2));
#else
                value = OrExpr::create(LShrExpr::create(value1, shift), ShlExpr::create(value2, shift2));
#endif

                // Trace the access
                std::vector<ref<Expr>> traceArgs;
                traceArgs.push_back(symbAddress);
                traceArgs.push_back(value);
                traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
                unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
                traceArgs.push_back(ConstantExpr::create(flags, Expr::Int64));
                traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
                handlerAfterMemoryAccess(executor, state, target, traceArgs);
            }
        } else {
/* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                do_unaligned_access(ENV_VAR addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;

            if (isWrite) {
                s2estate->writeMemory(addr + addend, value, HostAddress);
            } else {
                value = s2estate->readMemory(addr + addend, width, HostAddress);
            }

            // Trace the access
            std::vector<ref<Expr>> traceArgs;
            traceArgs.push_back(symbAddress);
            traceArgs.push_back(value);
            traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
            unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
            traceArgs.push_back(ConstantExpr::create(flags, Expr::Int64));
            traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
            handlerAfterMemoryAccess(executor, state, target, traceArgs);
        }
    } else {
/* the page is not in the TLB : fill it */
#ifdef ALIGNED_ONLY
        if ((addr & (data_size - 1)) != 0)
            do_unaligned_access(ENV_VAR addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
        tlb_fill(env, addr, object_index << SE_RAM_OBJECT_BITS, isWrite, mmu_idx, retaddr);
        goto redo;
    }

    if (!isWrite) {
        if (zeroExtend) {
            assert(data_size == 2);
            value = ZExtExpr::create(value, Expr::Int32);
        }
        // s2eExecutor->bindLocal(target, *state, value);
        return value;
    } else {
        return ref<Expr>();
    }
}

/* Replacement for ldl_kernel */
void S2EExecutor::handle_ldl_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                    std::vector<ref<Expr>> &args) {
    assert(args.size() == 1);
    handle_ldst_kernel(executor, state, target, args, false, 4, false, false);
}

void S2EExecutor::handle_ldq_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                    std::vector<ref<Expr>> &args) {
    assert(args.size() == 1);
    handle_ldst_kernel(executor, state, target, args, false, 8, false, false);
}

void S2EExecutor::handle_lduw_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                     std::vector<ref<Expr>> &args) {
    assert(args.size() == 1);
    handle_ldst_kernel(executor, state, target, args, false, 2, false, true);
}

/* Replacement for stl_kernel */
void S2EExecutor::handle_stl_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                    std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, true, 4, false, false);
}

void S2EExecutor::handle_stq_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                    std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, true, 8, false, false);
}

void S2EExecutor::handle_ldst_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                                     std::vector<ref<Expr>> &args, bool isWrite, unsigned data_size, bool signExtend,
                                     bool zeroExtend) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);
    S2EExecutor *s2eExecutor = static_cast<S2EExecutor *>(executor);
    unsigned mmu_idx = CPU_MMU_INDEX;

    ref<ConstantExpr> constantAddress = handleForkAndConcretizeNative(executor, state, target, args);

    Expr::Width width = data_size * 8;

    target_ulong addr = constantAddress->getZExtValue();
    target_ulong object_index, page_index;
    ref<Expr> value;
    uintptr_t physaddr;

    object_index = addr >> SE_RAM_OBJECT_BITS;
    page_index = (object_index >> S2E_RAM_OBJECT_DIFF) & (CPU_TLB_SIZE - 1);

    //////////////////////////////////////////

    if (isWrite) {
        value = args[1];
    }

    if (unlikely(env->tlb_table[mmu_idx][page_index].ADDR_READ != (addr & (TARGET_PAGE_MASK | (data_size - 1))))) {

        std::vector<ref<Expr>> slowArgs;

        if (isWrite) {
            slowArgs.push_back(constantAddress);
            slowArgs.push_back(value);
            slowArgs.push_back(ConstantExpr::create(mmu_idx, Expr::Int64));
            handle_ldst_mmu(executor, state, target, slowArgs, isWrite, data_size, signExtend, zeroExtend);
        } else {
            slowArgs.push_back(constantAddress);
            slowArgs.push_back(ConstantExpr::create(mmu_idx, Expr::Int64));
            value = handle_ldst_mmu(executor, state, target, slowArgs, isWrite, data_size, signExtend, zeroExtend);
            s2eExecutor->bindLocal(target, *state, value);
        }
        return;

    } else {
        // When we get here, the address is aligned with the size of the access,
        // which by definition means that it will fall inside the small page, without overflowing.
        physaddr = addr + env->tlb_table[mmu_idx][page_index].addend;

        if (isWrite) {
            s2estate->writeMemory(physaddr, value, HostAddress);
        } else {
            value = s2estate->readMemory(physaddr, width, HostAddress);
        }

        // Trace the access
        std::vector<ref<Expr>> traceArgs;
        traceArgs.push_back(constantAddress);
        traceArgs.push_back(value);
        traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
        unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
        traceArgs.push_back(ConstantExpr::create(flags, Expr::Int64));
        traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
        handlerAfterMemoryAccess(executor, state, target, traceArgs);

        if (!isWrite) {
            if (zeroExtend) {
                assert(data_size == 2);
                value = ZExtExpr::create(value, Expr::Int32);
            }
            s2eExecutor->bindLocal(target, *state, value);
        }
    }
}

S2EExecutor::HandlerInfo S2EExecutor::s_handlerInfo[] = {
#define add(name, handler) \
    { name, &S2EExecutor::handler }
    add("__ldb_mmu", handle_ldb_mmu), add("__ldw_mmu", handle_ldw_mmu), add("__ldl_mmu", handle_ldl_mmu),
    add("__stb_mmu", handle_stb_mmu), add("__stw_mmu", handle_stw_mmu), add("__stl_mmu", handle_stl_mmu),
    add("lduw_kernel", handle_lduw_kernel), add("ldl_kernel", handle_ldl_kernel),
    // add("stb_kernel", handle_stb_kernel),
    add("stl_kernel", handle_stl_kernel),

#ifdef TARGET_X86_64
    add("__stq_mmu", handle_stq_mmu), add("__ldq_mmu", handle_ldq_mmu), add("ldq_kernel", handle_ldq_kernel),
    add("stq_kernel", handle_stq_kernel),
#endif /* TARGET_X86_64 */

#undef add
};

void S2EExecutor::replaceExternalFunctionsWithSpecialHandlers() {
    unsigned N = sizeof(s_handlerInfo) / sizeof(s_handlerInfo[0]);

    for (unsigned i = 0; i < N; ++i) {
        HandlerInfo &hi = s_handlerInfo[i];
        llvm::Function *f = kmodule->module->getFunction(hi.name);
        assert(f);
        addSpecialFunctionHandler(f, hi.handler);
        overridenInternalFunctions.insert(f);
    }
}

static const char *s_disabledHelpers[] = {
    "helper_load_seg", "helper_iret_protected",
};

void S2EExecutor::disableConcreteLLVMHelpers() {
    unsigned N = sizeof(s_disabledHelpers) / sizeof(s_disabledHelpers[0]);

    for (unsigned i = 0; i < N; ++i) {
        llvm::Function *f = kmodule->module->getFunction(s_disabledHelpers[i]);
        assert(f && "Could not find required helper");
        kmodule->removeFunction(f, true);
    }
}
}
