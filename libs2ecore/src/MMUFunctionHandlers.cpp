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

/// @file
/// Native replacements for the softmmu entry points that translated code
/// calls when it runs in KLEE.
///
/// By default, KLEE interprets the bitcode of helper_{ld,st}*_mmu()
/// (libcpu/src/accel/cputlb.c). With the use-fast-helpers option, the handlers
/// below run instead. They do the same TLB lookup in C++ and read or write
/// the KLEE memory object directly, which avoids interpreting the lookup.
/// They make the whole address concrete, where the bitcode keeps the offset
/// inside the page symbolic.

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
#include <cpu/se_softmmu.h>

using namespace klee;

namespace s2e {

static ref<ConstantExpr> handleForkAndConcretizeNative(Executor *executor, ExecutionState *state,
                                                       klee::KInstruction *target, const ref<Expr> &symbAddress) {
    ref<ConstantExpr> constantAddress = dyn_cast<ConstantExpr>(symbAddress);
    if (!constantAddress) {
        // Find the LLVM instruction that computes the address
        const llvm::Instruction *addrInst = dyn_cast<llvm::Instruction>(target->inst->getOperand(0));
        auto kinst = target->owner->getInstruction(addrInst);
        assert(kinst);

        std::vector<ref<Expr>> forkArgs;
        forkArgs.push_back(symbAddress);
        forkArgs.push_back(ref<Expr>(nullptr));
        forkArgs.push_back(ref<Expr>(nullptr));
        forkArgs.push_back(0);
        handleForkAndConcretize(executor, state, kinst, forkArgs);

        constantAddress = dyn_cast<ConstantExpr>(state->llvm.getDestCell(kinst).value);
        assert(constantAddress);
    }
    return constantAddress;
}

static void traceAccess(Executor *executor, ExecutionState *state, klee::KInstruction *target, const ref<Expr> &address,
                        const ref<Expr> &value, unsigned size, unsigned flags) {
    auto corePlugin = g_s2e->getCorePlugin();
    if (corePlugin->onAfterSymbolicDataMemoryAccess.empty() && corePlugin->onConcreteDataMemoryAccess.empty()) {
        return;
    }

    std::vector<ref<Expr>> traceArgs;
    traceArgs.push_back(address);
    traceArgs.push_back(value);
    traceArgs.push_back(ConstantExpr::create(size, Expr::Int32));
    traceArgs.push_back(ConstantExpr::create(flags, Expr::Int64));
    traceArgs.push_back(ConstantExpr::create(0, Expr::Int64));
    handlerAfterMemoryAccess(executor, state, target, traceArgs);
}

/// Reads or writes a device register through the native softmmu. Devices
/// only take concrete values.
static ref<Expr> accessMmio(S2EExecutionState *state, CPUArchState *env, target_ulong addr, const ref<Expr> &value,
                            MemOpIdx oi, bool isWrite, unsigned size) {
    if (isWrite) {
        uint64_t v = state->concretize(value, "mmio write", false);
        switch (size) {
            case 1:
                cpu_stb_mmu(env, addr, v, oi, 0);
                break;
            case 2:
                cpu_stw_mmu(env, addr, v, oi, 0);
                break;
            case 4:
                cpu_stl_mmu(env, addr, v, oi, 0);
                break;
            case 8:
                cpu_stq_mmu(env, addr, v, oi, 0);
                break;
            default:
                abort();
        }
        return ref<Expr>();
    }

    uint64_t v;
    switch (size) {
        case 1:
            v = cpu_ldb_mmu(env, addr, oi, 0);
            break;
        case 2:
            v = cpu_ldw_mmu(env, addr, oi, 0);
            break;
        case 4:
            v = cpu_ldl_mmu(env, addr, oi, 0);
            break;
        case 8:
            v = cpu_ldq_mmu(env, addr, oi, 0);
            break;
        default:
            abort();
    }
    return ConstantExpr::create(v, size * 8);
}

/// Performs one guest memory access.
///
/// @param address the guest virtual address, possibly symbolic
/// @param value the value to store, size bytes wide; unused for loads
/// @return the value loaded, size bytes wide; null for stores
static ref<Expr> accessMemory(Executor *executor, ExecutionState *state, klee::KInstruction *target, CPUArchState *env,
                              const ref<Expr> &address, const ref<Expr> &value, MemOpIdx oi, bool isWrite,
                              unsigned size) {
    S2EExecutionState *s2estate = static_cast<S2EExecutionState *>(state);
    CPUState *cpu = env_cpu(env);
    const unsigned mmu_idx = get_mmuidx(oi);
    const MMUAccessType type = isWrite ? MMU_DATA_STORE : MMU_DATA_LOAD;
    const Expr::Width width = size * 8;

    ref<ConstantExpr> constantAddress = handleForkAndConcretizeNative(executor, state, target, address);
    target_ulong addr = constantAddress->getZExtValue();

    if (((addr & ~TARGET_PAGE_MASK) + size) > TARGET_PAGE_SIZE) {
        // The access spans two pages: do it one byte at a time, in guest
        // (little endian) byte order.
        ref<Expr> result;
        for (unsigned i = 0; i < size; ++i) {
            auto byteAddress = ConstantExpr::create((target_ulong) (addr + i), address->getWidth());
            MemOpIdx byteOi = make_memop_idx(MO_UB, mmu_idx);
            if (isWrite) {
                auto byte = ExtractExpr::create(value, i * 8, Expr::Int8);
                accessMemory(executor, state, target, env, byteAddress, byte, byteOi, true, 1);
            } else {
                auto byte = accessMemory(executor, state, target, env, byteAddress, ref<Expr>(), byteOi, false, 1);
                result = result ? ConcatExpr::create(byte, result) : byte;
            }
        }
        return result;
    }

    CPUTLBDescFast *fast = cpu_tlb_fast(cpu, mmu_idx);
    const uintptr_t index = (addr >> TARGET_PAGE_BITS) & (fast->mask >> CPU_TLB_ENTRY_BITS);
    const CPUTLBEntry *entry = &fast->table[index];
    uintptr_t tlb_addr = isWrite ? entry->addr_write : entry->addr_read;

    if ((addr & TARGET_PAGE_MASK) != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        // Not in the TLB. A guest fault leaves through the CPU loop and does
        // not come back here.
        x86_cpu_tlb_fill(cpu, addr, size, type, mmu_idx, false, 0);
        tlb_addr = isWrite ? entry->addr_write : entry->addr_read;
    }

    CPUTLBEntryFull *full = &cpu->neg.tlb.d[mmu_idx].fulltlb[index];
    int flags = tlb_addr & (TLB_FLAGS_MASK & ~TLB_FORCE_SLOW);
    flags |= full->slow_flags[type];

    if (flags & TLB_WATCHPOINT) {
        cpu_check_watchpoint(cpu, addr, size, full->attrs, isWrite ? BP_MEM_WRITE : BP_MEM_READ, 0);
    }

    ref<Expr> result;

    if (flags & TLB_MMIO) {
        result = accessMmio(s2estate, env, addr, value, oi, isWrite, size);
        traceAccess(executor, state, target, address, isWrite ? value : result, size,
                    (isWrite ? MEM_TRACE_FLAG_WRITE : 0) | MEM_TRACE_FLAG_IO);
        return result;
    }

    if (isWrite && (flags & TLB_NOTDIRTY)) {
        notdirty_write(cpu, addr, size, full, 0);
    }

    // KLEE binds the page at its address in guest RAM (addend). se_addend
    // points into the concrete buffer and is for natively executed code.
    const uint64_t host = addr + entry->addend;
    if (isWrite) {
        if (!(flags & TLB_DISCARD_WRITE)) {
            s2estate->mem()->write(host, value, HostAddress);
        }
    } else {
        result = s2estate->mem()->read(host, width, HostAddress);
    }

    traceAccess(executor, state, target, address, isWrite ? value : result, size, isWrite ? MEM_TRACE_FLAG_WRITE : 0);
    return result;
}

/// Handles helper_ld{ub,uw,ul,q,sb,sw,sl}_mmu(env, addr, oi, retaddr). They
/// return a register-sized value, zero or sign extended.
template <unsigned SIZE, bool SIGNED>
static void handleLoad(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                       std::vector<ref<Expr>> &args) {
    assert(args.size() == 4);
    auto env = (CPUArchState *) cast<ConstantExpr>(args[0])->getZExtValue();
    MemOpIdx oi = cast<ConstantExpr>(args[2])->getZExtValue();

    ref<Expr> value = accessMemory(executor, state, target, env, args[1], ref<Expr>(), oi, false, SIZE);

    const Expr::Width retWidth = sizeof(tcg_target_ulong) * 8;
    if (value->getWidth() < retWidth) {
        value = SIGNED ? SExtExpr::create(value, retWidth) : ZExtExpr::create(value, retWidth);
    }
    state->llvm.bindLocal(target, value);
}

/// Handles helper_st{b,w,l,q}_mmu(env, addr, val, oi, retaddr). The value
/// argument can be wider than the access.
template <unsigned SIZE>
static void handleStore(Executor *executor, ExecutionState *state, klee::KInstruction *target,
                        std::vector<ref<Expr>> &args) {
    assert(args.size() == 5);
    auto env = (CPUArchState *) cast<ConstantExpr>(args[0])->getZExtValue();
    MemOpIdx oi = cast<ConstantExpr>(args[3])->getZExtValue();

    ref<Expr> value = args[2];
    if (value->getWidth() > SIZE * 8) {
        value = ExtractExpr::create(value, 0, SIZE * 8);
    }

    accessMemory(executor, state, target, env, args[1], value, oi, true, SIZE);
}

static Handler s_handlerInfo[] = {
#define add(name, handler) {name, &handler, nullptr}
    add("helper_ldub_mmu", (handleLoad<1, false>) ), add("helper_lduw_mmu", (handleLoad<2, false>) ),
    add("helper_ldul_mmu", (handleLoad<4, false>) ), add("helper_ldq_mmu", (handleLoad<8, false>) ),
    add("helper_ldsb_mmu", (handleLoad<1, true>) ),  add("helper_ldsw_mmu", (handleLoad<2, true>) ),
    add("helper_ldsl_mmu", (handleLoad<4, true>) ),  add("helper_stb_mmu", handleStore<1>),
    add("helper_stw_mmu", handleStore<2>),           add("helper_stl_mmu", handleStore<4>),
    add("helper_stq_mmu", handleStore<8>),
#undef add
};

void S2EExecutor::replaceExternalFunctionsWithSpecialHandlers() {
    unsigned N = sizeof(s_handlerInfo) / sizeof(s_handlerInfo[0]);

    for (unsigned i = 0; i < N; ++i) {
        const auto &hi = s_handlerInfo[i];
        auto f = m_kmodule->getModule()->getFunction(hi.name);
        assert(f);
        addSpecialFunctionHandler(f, hi.handler);
        m_overridenInternalFunctions.insert(f);
    }
}

static const char *s_disabledHelpers[] = {
    "helper_load_seg",
    "helper_iret_protected",
};

void S2EExecutor::disableConcreteLLVMHelpers() {
    unsigned N = sizeof(s_disabledHelpers) / sizeof(s_disabledHelpers[0]);

    for (unsigned i = 0; i < N; ++i) {
        llvm::Function *f = m_kmodule->getModule()->getFunction(s_disabledHelpers[i]);
        assert(f && "Could not find required helper");
        m_kmodule->removeFunction(f, true);
    }
}
} // namespace s2e
