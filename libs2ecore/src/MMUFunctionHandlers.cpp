///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#include <s2e/cpu.h>

#include <s2e/CorePlugin.h>
#include <s2e/FunctionHandlers.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/s2e_libcpu.h>

#include <llvm/IR/Module.h>

#include <cpu/memory.h>

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
static void io_write_chk(S2EExecutionState *state, CPUArchState *env, target_phys_addr_t physaddr, const ref<Expr> &val,
                         target_ulong addr, void *retaddr, Expr::Width width) {
    target_phys_addr_t origaddr = physaddr;
    uint64_t concreteVal;
    const struct MemoryDescOps *ops = phys_get_ops(physaddr);
    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;

    state->setMemIoVaddr(ConstantExpr::create(addr, sizeof(target_ulong) * 8));
    env->mem_io_pc = (uintptr_t) retaddr;

    if (width <= Expr::Int32) {
        if (se_ismemfunc(ops, 1)) {
            uintptr_t pa = se_notdirty_mem_write(physaddr, Expr::getMinBytesForWidth(width));
            state->mem()->write(pa, val, HostAddress);
            goto end;
        }
    } else {
#ifdef TARGET_WORDS_BIGENDIAN
#error Big endian not supported
#else
        if (se_ismemfunc(ops, 1)) {
            uintptr_t pa = se_notdirty_mem_write(physaddr, Expr::getMinBytesForWidth(width));
            state->mem()->write(pa, ExtractExpr::create(val, 0, Expr::Int32), HostAddress);
            pa = se_notdirty_mem_write(physaddr + 4, Expr::getMinBytesForWidth(width));
            state->mem()->write(pa, LShrExpr::create(val, ConstantExpr::create(32, width)), HostAddress);
            goto end;
        }
#endif
    }

    concreteVal = state->concretize(val, "io_write_chk", false);
    switch (width) {
        case Expr::Int8:
            io_writeb_mmu(env, origaddr, concreteVal, addr, retaddr);
            break;
        case Expr::Int16:
            io_writew_mmu(env, origaddr, concreteVal, addr, retaddr);
            break;
        case Expr::Int32:
            io_writel_mmu(env, origaddr, concreteVal, addr, retaddr);
            break;
        case Expr::Int64:
            io_writeq_mmu(env, origaddr, concreteVal, addr, retaddr);
            break;
        default:
            abort();
    }

end:
    // XXX: handle memory access
    // tcg_llvm_trace_mmio_access(addr, val, Expr::getMinBytesForWidth(width), 1);
    state->setMemIoVaddr(nullptr);
}

// This is an io_read_chkX_mmu function
static ref<Expr> io_read_chk(S2EExecutionState *state, const CPUTLBEntry &tlb, target_phys_addr_t physaddr,
                             target_ulong addr, void *retaddr, Expr::Width width) {
    uint64_t r;
    unsigned bw;
    ref<Expr> ret;
    target_phys_addr_t origaddr = physaddr;
    const struct MemoryDescOps *ops = phys_get_ops(physaddr);

    target_ulong naddr = (physaddr & TARGET_PAGE_MASK) + addr;

    env->mem_io_pc = (uintptr_t) retaddr;
    state->setMemIoVaddr(ConstantExpr::create(addr, sizeof(target_ulong) * 8));

    if (is_notdirty_ops(ops)) {
        ret = state->mem()->read(tlb.addend + addr, width, HostAddress);
        goto end;
    }

    bw = Expr::getMinBytesForWidth(width);

    if (bw <= 4) {
        if (se_ismemfunc(ops, 0)) {
            uintptr_t pa = se_notdirty_mem_read(naddr);
            ret = state->mem()->read(pa, width, HostAddress);
            goto end;
        }
    } else {
#ifdef TARGET_WORDS_BIGENDIAN
        abort();
#else
        if (se_ismemfunc(ops, 0)) {
            uintptr_t pa = se_notdirty_mem_read(naddr);
            auto e1 = state->mem()->read(pa, width, HostAddress);

            pa = se_notdirty_mem_read(naddr + 4);
            auto e2 = state->mem()->read(pa, width, HostAddress);

            ret = ConcatExpr::create(e2, e1);
            goto end;
        }
#endif
    }

    switch (bw) {
        case 1:
            r = io_readb_mmu(env, origaddr, addr, retaddr);
            break;
        case 2:
            r = io_readw_mmu(env, origaddr, addr, retaddr);
            break;
        case 4:
            r = io_readl_mmu(env, origaddr, addr, retaddr);
            break;
        case 8:
            r = io_readq_mmu(env, origaddr, addr, retaddr);
            break;
        default:
            abort();
    }

    ret = ConstantExpr::create(r, width);
end:
    // TODO: trace mmio
    state->setMemIoVaddr(nullptr);
    return ret;
}

static ref<ConstantExpr> handleForkAndConcretizeNative(Executor *executor, ExecutionState *state,
                                                       klee::KInstruction *target, const ref<Expr> &symbAddress) {
    ref<ConstantExpr> constantAddress = dyn_cast<ConstantExpr>(symbAddress);
    if (constantAddress.isNull()) {
        // Find the LLVM instruction that computes the address
        const llvm::Instruction *addrInst = dyn_cast<llvm::Instruction>(target->inst->getOperand(0));
        assert(target->owner->instrMap.count(addrInst));

        std::vector<ref<Expr>> forkArgs;
        forkArgs.push_back(symbAddress);
        forkArgs.push_back(ref<Expr>(nullptr));
        forkArgs.push_back(ref<Expr>(nullptr));
        forkArgs.push_back(0);
        KInstruction *kinst = (*target->owner->instrMap.find(addrInst)).second;
        handleForkAndConcretize(executor, state, kinst, forkArgs);

        constantAddress = dyn_cast<ConstantExpr>(state->getDestCell(kinst).value);
        assert(!constantAddress.isNull());
    }
    return constantAddress;
}

template <typename V>
static ref<Expr> handle_ldst_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target, const V &args,
                                 bool isWrite, unsigned data_size, bool signExtend, bool zeroExtend) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);

    ref<ConstantExpr> envExpr = dyn_cast<ConstantExpr>(args[0]);
    assert(!envExpr.isNull());
    CPUArchState *env = (CPUArchState *) envExpr->getZExtValue();

    const auto &symbAddress = args[1];
    ref<ConstantExpr> constantAddress = handleForkAndConcretizeNative(executor, state, target, symbAddress);

    ref<Expr> mmuIdxExpr = args[isWrite ? 3 : 2];
    unsigned mmu_idx = dyn_cast<ConstantExpr>(mmuIdxExpr)->getZExtValue() & 0xf;

    // XXX: determine this by looking at the instruction that called us
    Expr::Width width = data_size * 8;
    Expr::Width addressWidth = symbAddress->getWidth();

    target_ulong addr = constantAddress->getZExtValue();
    target_ulong object_index, index;
    ref<Expr> value;
    target_ulong tlb_addr, addr1, addr2;
    target_phys_addr_t addend, ioaddr;
    void *retaddr = nullptr;

    if (isWrite) {
        value = args[2];
        assert(value->getWidth() == width);
    }

    object_index = addr >> SE_RAM_OBJECT_BITS;
    index = (object_index >> S2E_RAM_OBJECT_DIFF) & (CPU_TLB_SIZE - 1);

redo:

    const auto &tlbEntry = env->tlb_table[mmu_idx][index];

    if (isWrite) {
        tlb_addr = tlbEntry.addr_write & ~TLB_MEM_TRACE;
    } else {
        tlb_addr = tlbEntry.addr_read & ~TLB_MEM_TRACE;
    }

    if (likely((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK)))) {
        if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
            /* IO access */
            if ((addr & (data_size - 1)) != 0) {
                goto do_unaligned_access;
            }

            ioaddr = env->iotlb[mmu_idx][index];

            if (!isWrite) {
                value = io_read_chk(s2estate, tlbEntry, ioaddr, addr, retaddr, width);
            }

            auto corePlugin = g_s2e->getCorePlugin();
            if (!corePlugin->onAfterSymbolicDataMemoryAccess.empty() ||
                !corePlugin->onConcreteDataMemoryAccess.empty()) {
                // Trace the access
                std::vector<ref<Expr>> traceArgs;
                traceArgs.push_back(symbAddress);
                traceArgs.push_back(value);
                traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
                unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
                traceArgs.push_back(ConstantExpr::create(flags | MEM_TRACE_FLAG_IO, Expr::Int64));
                traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
                handlerAfterMemoryAccess(executor, state, target, traceArgs);
            }

            if (isWrite) {
                io_write_chk(s2estate, env, ioaddr, value, addr, retaddr, width);
            }

        } else if (unlikely(((addr & ~SE_RAM_OBJECT_MASK) + data_size - 1) >= SE_RAM_OBJECT_SIZE)) {
        /* slow unaligned access (it spans two pages or IO) */
        do_unaligned_access:

            if (isWrite) {
                for (int i = data_size - 1; i >= 0; i--) {
                    HandlerArgs unalignedAccessArgs;
#ifdef TARGET_WORDS_BIGENDIAN
                    ref<Expr> shiftCount = ConstantExpr::create((((data_size - 1) * 8) - (i * 8)), width);
#else
                    ref<Expr> shiftCount = ConstantExpr::create(i * 8, width);
#endif

                    ref<Expr> shiftedValue = LShrExpr::create(value, shiftCount);
                    ref<Expr> resizedValue = ExtractExpr::create(shiftedValue, 0, Expr::Int8);
                    unalignedAccessArgs.push_back(args[0]);
                    unalignedAccessArgs.push_back(ConstantExpr::create(addr + i, addressWidth));
                    unalignedAccessArgs.push_back(resizedValue);
                    unalignedAccessArgs.push_back(mmuIdxExpr);
                    unalignedAccessArgs.push_back(args[3]);
                    handle_ldst_mmu(executor, state, target, unalignedAccessArgs, true, 1, false, false);
                }
            } else {
                addr1 = addr & ~((target_ulong) data_size - 1);
                addr2 = addr1 + (target_ulong) data_size;

                HandlerArgs unalignedAccessArgs;
                unalignedAccessArgs.push_back(args[0]);
                unalignedAccessArgs.push_back(ConstantExpr::create(addr1, addressWidth));
                unalignedAccessArgs.push_back(mmuIdxExpr);
                unalignedAccessArgs.push_back(args[2]);
                ref<Expr> value1 = handle_ldst_mmu(executor, state, target, unalignedAccessArgs, isWrite, data_size,
                                                   signExtend, zeroExtend);

                unalignedAccessArgs[1] = ConstantExpr::create(addr2, addressWidth);
                ref<Expr> value2 = handle_ldst_mmu(executor, state, target, unalignedAccessArgs, isWrite, data_size,
                                                   signExtend, zeroExtend);

                ref<Expr> shift = ConstantExpr::create((addr & (data_size - 1)) * 8, width);
                ref<Expr> shift2 = ConstantExpr::create((data_size * 8) - ((addr & (data_size - 1)) * 8), width);

#ifdef TARGET_WORDS_BIGENDIAN
                value = OrExpr::create(ShlExpr::create(value1, shift), LShrExpr::create(value2, shift2));
#else
                value = OrExpr::create(LShrExpr::create(value1, shift), ShlExpr::create(value2, shift2));
#endif

                auto corePlugin = g_s2e->getCorePlugin();
                if (!corePlugin->onAfterSymbolicDataMemoryAccess.empty() ||
                    !corePlugin->onConcreteDataMemoryAccess.empty()) {
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
            }
        } else {
/* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                do_unaligned_access(ENV_VAR addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
            }
#endif
            addend = tlbEntry.addend;

            if (isWrite) {
                s2estate->mem()->write(addr + addend, value, HostAddress);
            } else {
                value = s2estate->mem()->read(addr + addend, width, HostAddress);
            }

            auto corePlugin = g_s2e->getCorePlugin();
            if (!corePlugin->onAfterSymbolicDataMemoryAccess.empty() ||
                !corePlugin->onConcreteDataMemoryAccess.empty()) {
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
        }
    } else {
        /* the page is not in the TLB : fill it */
        tlb_fill(env, addr, object_index << SE_RAM_OBJECT_BITS, isWrite, mmu_idx, retaddr);
        goto redo;
    }

    if (!isWrite) {
        if (zeroExtend) {
            assert(data_size == 2);
            value = ZExtExpr::create(value, Expr::Int32);
        }
        return value;
    } else {
        return ref<Expr>();
    }
}

static void handle_ldb_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 4);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 1, false, false);
    assert(value->getWidth() == Expr::Int8);
    state->bindLocal(target, value);
}

static void handle_ldw_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 4);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 2, false, false);
    assert(value->getWidth() == Expr::Int16);
    state->bindLocal(target, value);
}

static void handle_ldl_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 4);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 4, false, false);
    assert(value->getWidth() == Expr::Int32);
    state->bindLocal(target, value);
}

static void handle_ldq_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 4);
    ref<Expr> value = handle_ldst_mmu(executor, state, target, args, false, 8, false, false);
    assert(value->getWidth() == Expr::Int64);
    state->bindLocal(target, value);
}

static void handle_stb_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 5);
    handle_ldst_mmu(executor, state, target, args, true, 1, false, false);
}

static void handle_stw_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 5);
    handle_ldst_mmu(executor, state, target, args, true, 2, false, false);
}

static void handle_stl_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 5);
    handle_ldst_mmu(executor, state, target, args, true, 4, false, false);
}

static void handle_stq_mmu(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                           std::vector<ref<Expr>> &args) {
    assert(args.size() == 5);
    handle_ldst_mmu(executor, state, target, args, true, 8, false, false);
}

static void handle_ldst_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                               std::vector<ref<Expr>> &args, bool isWrite, unsigned dataSize, bool signExtend,
                               bool zeroExtend) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);
    unsigned mmu_idx = CPU_MMU_INDEX;

    ref<ConstantExpr> envExpr = dyn_cast<ConstantExpr>(args[0]);
    assert(!envExpr.isNull());
    CPUArchState *env = (CPUArchState *) envExpr->getZExtValue();

    const auto &symbAddress = args[1];
    ref<ConstantExpr> constantAddress = handleForkAndConcretizeNative(executor, state, target, symbAddress);

    Expr::Width width = dataSize * 8;
    target_ulong addr = constantAddress->getZExtValue();
    target_ulong object_index, page_index, tlb_addr;
    ref<Expr> value;
    uintptr_t physaddr;

    object_index = addr >> SE_RAM_OBJECT_BITS;
    page_index = (object_index >> S2E_RAM_OBJECT_DIFF) & (CPU_TLB_SIZE - 1);

    //////////////////////////////////////////
    const auto &tlbEntry = env->tlb_table[mmu_idx][page_index];

    if (isWrite) {
        value = args[2];
        if (value->getWidth() > width) {
            value = ExtractExpr::create(value, 0, width);
        }

        tlb_addr = tlbEntry.addr_write & ~TLB_MEM_TRACE;
    } else {
        tlb_addr = tlbEntry.addr_read & ~TLB_MEM_TRACE;
    }

    if (unlikely(tlb_addr != (addr & (TARGET_PAGE_MASK | (dataSize - 1))))) {

        HandlerArgs slowArgs;

        if (isWrite) {
            slowArgs.push_back(envExpr);
            slowArgs.push_back(constantAddress);
            slowArgs.push_back(value);
            slowArgs.push_back(ConstantExpr::create(mmu_idx, Expr::Int64));
            slowArgs.push_back(ConstantExpr::create(0, Expr::Int64));
            handle_ldst_mmu(executor, state, target, slowArgs, isWrite, dataSize, signExtend, zeroExtend);
        } else {
            slowArgs.push_back(envExpr);
            slowArgs.push_back(constantAddress);
            slowArgs.push_back(ConstantExpr::create(mmu_idx, Expr::Int64));
            slowArgs.push_back(ConstantExpr::create(0, Expr::Int64));
            value = handle_ldst_mmu(executor, state, target, slowArgs, isWrite, dataSize, signExtend, zeroExtend);
            state->bindLocal(target, value);
        }
        return;

    } else {
        // When we get here, the address is aligned with the size of the access,
        // which by definition means that it will fall inside the small page, without overflowing.
        physaddr = addr + tlbEntry.addend;

        if (isWrite) {
            s2estate->mem()->write(physaddr, value, HostAddress);
        } else {
            value = s2estate->mem()->read(physaddr, width, HostAddress);
        }

        // Trace the access
        // TODO: don't do this if there is no instrumentation
        auto corePlugin = g_s2e->getCorePlugin();
        if (!corePlugin->onAfterSymbolicDataMemoryAccess.empty() || !corePlugin->onConcreteDataMemoryAccess.empty()) {
            std::vector<ref<Expr>> traceArgs;
            traceArgs.push_back(constantAddress);
            traceArgs.push_back(value);
            traceArgs.push_back(ConstantExpr::create(width / 8, Expr::Int32));
            unsigned flags = isWrite ? MEM_TRACE_FLAG_WRITE : 0;
            traceArgs.push_back(ConstantExpr::create(flags, Expr::Int64));
            traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
            handlerAfterMemoryAccess(executor, state, target, traceArgs);
        }

        if (!isWrite) {
            if (zeroExtend) {
                assert(dataSize < 4);
                value = ZExtExpr::create(value, Expr::Int32);
            }
            state->bindLocal(target, value);
        }
    }
}

static void handle_ldub_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                               std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, false, 1, false, true);
}

static void handle_lduw_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                               std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, false, 2, false, true);
}

// TODO: implement lds
static void handle_ldl_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, false, 4, false, false);
}

#ifdef TARGET_X86_64
static void handle_ldq_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 2);
    handle_ldst_kernel(executor, state, target, args, false, 8, false, false);
}
#endif

static void handle_stb_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_kernel(executor, state, target, args, true, 1, false, false);
}

static void handle_stw_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_kernel(executor, state, target, args, true, 2, false, false);
}

static void handle_stl_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_kernel(executor, state, target, args, true, 4, false, false);
}

#ifdef TARGET_X86_64
static void handle_stq_kernel(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                              std::vector<ref<Expr>> &args) {
    assert(args.size() == 3);
    handle_ldst_kernel(executor, state, target, args, true, 8, false, false);
}
#endif

static Handler s_handlerInfo[] = {
#define add(name, handler) \
    { name, &handler, nullptr }
    add("helper_ldb_mmu", handle_ldb_mmu),
    add("helper_ldw_mmu", handle_ldw_mmu),
    add("helper_ldl_mmu", handle_ldl_mmu),
    add("helper_ldq_mmu", handle_ldq_mmu),
    add("helper_stb_mmu", handle_stb_mmu),
    add("helper_stw_mmu", handle_stw_mmu),
    add("helper_stl_mmu", handle_stl_mmu),
    add("helper_stq_mmu", handle_stq_mmu),
    add("cpu_stb_kernel", handle_stb_kernel),
    add("cpu_stw_kernel", handle_stw_kernel),
    add("cpu_stl_kernel", handle_stl_kernel),
    add("cpu_ldub_kernel", handle_ldub_kernel),
    add("cpu_lduw_kernel", handle_lduw_kernel),
    add("cpu_ldl_kernel", handle_ldl_kernel),

#ifdef TARGET_X86_64
    add("helper_ldq_mmu", handle_ldq_mmu),
    add("helper_stq_mmu", handle_stq_mmu),
    add("cpu_ldq_kernel", handle_ldq_kernel),
    add("cpu_stq_kernel", handle_stq_kernel)
#endif /* TARGET_X86_64 */

#undef add
};

void S2EExecutor::replaceExternalFunctionsWithSpecialHandlers() {
    unsigned N = sizeof(s_handlerInfo) / sizeof(s_handlerInfo[0]);

    for (unsigned i = 0; i < N; ++i) {
        const auto &hi = s_handlerInfo[i];
        auto f = kmodule->module->getFunction(hi.name);
        assert(f);
        addSpecialFunctionHandler(f, hi.handler);
        overridenInternalFunctions.insert(f);
    }
}

static const char *s_disabledHelpers[] = {
    "helper_load_seg",
    "helper_iret_protected",
};

void S2EExecutor::disableConcreteLLVMHelpers() {
    unsigned N = sizeof(s_disabledHelpers) / sizeof(s_disabledHelpers[0]);

    for (unsigned i = 0; i < N; ++i) {
        llvm::Function *f = kmodule->module->getFunction(s_disabledHelpers[i]);
        assert(f && "Could not find required helper");
        kmodule->removeFunction(f, true);
    }
}
} // namespace s2e
