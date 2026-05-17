///
/// Copyright (C) 2026, Vitaly Chipounov
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

#include <functional>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"

#include <klee/ExecutionState.h>
#include <klee/Executor.h>
#include <klee/Expr.h>
#include <klee/Internal/Module/KInstruction.h>
#include <klee/Internal/Module/KModule.h>
#include <klee/LLVMExecutionState.h>

using namespace klee;
using namespace llvm;

/// Native helper used as a concrete function pointer in FunctionPointerIndirectCall.
///
/// Must live outside the anonymous namespace and carry C linkage so that its
/// address is a callable symbol the external dispatcher can invoke directly.
extern "C" int native_triple(int x) {
    return x * 3;
}

namespace {

/// Minimal Executor subclass for unit testing.
///
/// Implements fork() as a no-op since tests only use concrete values.
/// Exposes the protected eval() and executeInstruction() to drive a
/// step-by-step execution loop from outside the class.
///
/// The constructor either creates an empty module (with a standard x86-64 data
/// layout) or loads one from a bitcode file.  In both cases the module is owned
/// by the executor and activated automatically; callers cannot replace it.
class TestExecutor : public Executor {
    llvm::LLVMContext &m_ctx;
    std::unique_ptr<llvm::Module> m_ownedModule;
    KFunction *m_dummyMain = nullptr;

    static constexpr const char *kStdLayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128";

    /// Override setModule to inject a no-op dummy entry-point function.
    ///
    /// The dummy serves as the initial stack frame (matching S2E's m_dummyMain
    /// pattern) so that runFunction() can push real functions on top of it via
    /// pushFrame without underflowing the stack.
    ///
    /// Private: callers must not replace the module after construction.
    const llvm::Module *setModule(llvm::Module *module) override {
        auto *result = Executor::setModule(module);

        auto *dummyFn = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(m_ctx), false),
                                               llvm::Function::ExternalLinkage, "__test_main", module);
        llvm::ReturnInst::Create(m_ctx, llvm::BasicBlock::Create(m_ctx, "entry", dummyFn));
        m_dummyMain = m_kmodule->updateModuleWithFunction(dummyFn);

        return result;
    }

    void initEmpty() {
        m_ownedModule = std::make_unique<llvm::Module>("", m_ctx);
        m_ownedModule->setDataLayout(kStdLayout);
        setModule(m_ownedModule.get());
    }

    void initFromBitcode(const char *path) {
        auto bufOrErr = llvm::MemoryBuffer::getFile(path);
        assert(bufOrErr && "failed to open bitcode file");
        auto modOrErr = llvm::parseBitcodeFile(bufOrErr.get()->getMemBufferRef(), m_ctx);
        assert(modOrErr && "failed to parse bitcode file");
        m_ownedModule = std::move(modOrErr.get());
        setModule(m_ownedModule.get());
    }

public:
    /// Construct an executor backed by an empty module (no bitcodeFile) or by
    /// the module loaded from \p bitcodeFile.  The module is owned and
    /// activated by the constructor; setModule() is not accessible to callers.
    explicit TestExecutor(llvm::LLVMContext &ctx, const char *bitcodeFile = nullptr) : Executor(ctx), m_ctx(ctx) {
        if (bitcodeFile) {
            initFromBitcode(bitcodeFile);
        } else {
            initEmpty();
        }
    }

    StatePair fork(ExecutionState &current, const ref<Expr> &condition, bool keepConditionTrueInCurrentState,
                   std::function<void(ExecutionStatePtr, const StatePair &)> onBeforeNotify) override {
        StatePair sp;
        if (auto *ce = dyn_cast<klee::ConstantExpr>(condition)) {
            sp = ce->isTrue() ? StatePair(&current, nullptr) : StatePair(nullptr, &current);
        } else {
            abort();
        }
        onBeforeNotify(&current, sp);
        return sp;
    }

    /// Return the underlying LLVM module.
    ///
    /// Tests that build IR programmatically use this to add functions before
    /// passing them to runFunction().
    llvm::Module *getLLVMModule() {
        return m_ownedModule.get();
    }

    /// Create an execution state whose initial frame is the dummy entry point.
    ///
    /// Globals are initialized and module constants bound before returning.
    ExecutionStatePtr createState() {
        auto state = ExecutionStatePtr(new ExecutionState(m_dummyMain));
        initializeGlobals(*state);
        m_kmodule->bindModuleConstants(m_globalAddresses);
        return state;
    }

    /// Set up \p fn as a call from the current dummy frame (mirroring
    /// S2EExecutor::prepareFunctionExecution), execute it, and return its
    /// return-value expression.  nullptr is returned for void functions.
    ref<Expr> runFunction(ExecutionState &state, llvm::Function *fn, std::vector<ref<Expr>> args) {
        auto *kf = m_kmodule->bindFunctionConstants(m_globalAddresses, fn);

        state.llvm.prevPC = state.llvm.pc;
        state.llvm.pushFrame(state.llvm.pc, kf);
        state.llvm.pc = kf->getInstructions();

        for (unsigned i = 0; i < args.size(); ++i)
            state.llvm.bindArgument(kf, i, args[i]);

        // Run until the Ret that belongs to this invocation.
        unsigned targetDepth = state.llvm.stack.size();
        while (state.llvm.stack.size() >= targetDepth) {
            KInstruction *ki = state.llvm.pc;

            if (state.llvm.stack.size() == targetDepth && ki->inst->getOpcode() == Instruction::Ret) {
                auto *ri = cast<ReturnInst>(ki->inst);
                if (ri->getNumOperands() == 0)
                    return nullptr;
                return eval(ki, 0, state.llvm).value;
            }

            state.llvm.stepInstruction();
            executeInstruction(state, ki);
        }
        return nullptr;
    }

    /// Execute the state until a ret instruction is reached.
    ///
    /// Stops just before executing ret so that the caller can inspect
    /// the return value without triggering the stack-underflow check
    /// inside executeInstruction().
    ///
    /// \returns the return-value expression, or nullptr for void returns.
    ref<Expr> runUntilReturn(ExecutionState &state) {
        while (state.llvm.pc) {
            KInstruction *ki = state.llvm.pc;
            // llvm::outs() << *ki->inst << "\n";

            if (ki->inst->getOpcode() == Instruction::Ret) {
                auto *ri = cast<ReturnInst>(ki->inst);
                if (ri->getNumOperands() == 0) {
                    return nullptr;
                }
                // Read the return value from the virtual register file before
                // the frame is popped.
                return eval(ki, 0, state.llvm).value;
            }

            state.llvm.stepInstruction();
            executeInstruction(state, ki);
        }
        return nullptr;
    }
};

// ============================================================
// Test: add(int, int) - simple two-value addition
// ============================================================

TEST(ExecutorTest, ConcreteAddReturnsCorrectValue) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, ADD_BC_PATH);

    llvm::Function *fn = executor.getLLVMModule()->getFunction("add");
    ASSERT_NE(fn, nullptr) << "Function 'add' not found in module";

    ExecutionStatePtr state = executor.createState();

    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(5, Expr::Int32), klee::ConstantExpr::create(3, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr) << "Expected a constant (concrete) expression";
    EXPECT_EQ(ce->getZExtValue(), 8u);
}

// ============================================================
// Test: GEP struct field offset
//
// Builds the following IR programmatically and executes it:
//
//   %S = type { [8 x i32], i32, i32 }
//   define ptr @gep_field(ptr %p) {
//     %r = getelementptr inbounds %S, ptr %p, i32 0, i32 1
//     ret ptr %r
//   }
//
// Field 1 of { [8 x i32], i32, i32 } is at byte offset 32.
// The test asserts that the returned address equals the base + 32.
// ============================================================

TEST(ExecutorTest, GEPStructFieldReturnsCorrectOffset) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *arrTy = llvm::ArrayType::get(i32Ty, 8);
    auto *structTy = llvm::StructType::create(ctx, {arrTy, i32Ty, i32Ty}, "S");

    auto *ptrTy = llvm::PointerType::getUnqual(ctx);
    auto *fnTy = llvm::FunctionType::get(ptrTy, {ptrTy}, /*isVarArg=*/false);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();

    auto *fn = llvm::Function::Create(fnTy, llvm::Function::ExternalLinkage, "gep_field", mod);
    auto *bb = llvm::BasicBlock::Create(ctx, "entry", fn);
    llvm::IRBuilder<> builder(bb);
    auto *gep = builder.CreateStructGEP(structTy, fn->getArg(0), 1);
    builder.CreateRet(gep);

    ExecutionStatePtr state = executor.createState();

    constexpr uint64_t fakeBase = 0x1000;
    unsigned ptrWidth = executor.getModule()->getDataLayout()->getPointerSizeInBits();
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(fakeBase, ptrWidth)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr) << "Expected a concrete pointer expression";
    // { [8 x i32], i32, i32 }: field 1 starts after 8*4 = 32 bytes.
    EXPECT_EQ(ce->getZExtValue(), fakeBase + 32u);
}

// ============================================================
// Test: compute(Input*, Output*) - aggregate statistics
// ============================================================

/// Must match the layout declared in compute.c exactly.
struct Input {
    int values[8];
    int n;
    unsigned flags;
};

struct Output {
    int sum;
    int min_val;
    int max_val;
    unsigned xor_all;
    unsigned and_masked;
    int alternating;
    int dot_self;
};

TEST(ExecutorTest, ComputeAggregateStatistics) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, COMPUTE_BC_PATH);

    llvm::Function *fn = executor.getLLVMModule()->getFunction("compute");
    ASSERT_NE(fn, nullptr) << "Function 'compute' not found in module";

    // Set up concrete input/output in host memory and expose them to KLEE.
    Input in = {};
    in.values[0] = 1;
    in.values[1] = -2;
    in.values[2] = 3;
    in.values[3] = -4;
    in.values[4] = 5;
    in.n = 5;
    in.flags = 0xFFFFFFFFu;

    Output out = {};

    ExecutionStatePtr state = executor.createState();

    // Register host structs in the KLEE address space.
    // isSharedConcrete=false: KLEE copies `in` into its own concrete buffer
    // (reads will be served from that buffer) and writes to `out` go into
    // KLEE's buffer (read back via the address space after execution).
    state->addExternalObject(&in, sizeof(in), /*isReadOnly=*/true, /*isSharedConcrete=*/false);
    state->addExternalObject(&out, sizeof(out), /*isReadOnly=*/false, /*isSharedConcrete=*/false);

    // Pass pointer arguments as concrete addresses matching the host addresses
    // that were registered with the address space above.
    unsigned ptrWidth = executor.getModule()->getDataLayout()->getPointerSizeInBits();
    executor.runFunction(
        *state, fn,
        {klee::ConstantExpr::create((uint64_t) &in, ptrWidth), klee::ConstantExpr::create((uint64_t) &out, ptrWidth)});

    // Read output fields back from the KLEE address space.
    auto readI32 = [&](uint64_t addr) -> int32_t {
        auto e = state->addressSpace().read(addr, klee::Expr::Int32);
        auto *ce = dyn_cast<klee::ConstantExpr>(e);
        return ce ? (int32_t) ce->getZExtValue() : 0;
    };
    auto readU32 = [&](uint64_t addr) -> uint32_t {
        auto e = state->addressSpace().read(addr, klee::Expr::Int32);
        auto *ce = dyn_cast<klee::ConstantExpr>(e);
        return ce ? (uint32_t) ce->getZExtValue() : 0;
    };

    uint64_t outAddr = (uint64_t) &out;

    // Compute expected values for {1, -2, 3, -4, 5}, flags=0xFFFFFFFF.
    // sum          = 1 + (-2) + 3 + (-4) + 5 = 3
    // min_val      = -4
    // max_val      = 5
    // xor_all      = 1 ^ (-2) ^ 3 ^ (-4) ^ 5  (unsigned bitwise)
    // and_masked   = 0xFFFFFFFF & 1 & (-2) & 3 & (-4) & 5
    // alternating  = 1 - (-2) + 3 - (-4) + 5 = 15
    // dot_self     = 1 + 4 + 9 + 16 + 25 = 55

    unsigned xor_expected = 1u ^ (unsigned) -2 ^ 3u ^ (unsigned) -4 ^ 5u;
    unsigned and_expected = 0xFFFFFFFFu & 1u & (unsigned) -2 & 3u & (unsigned) -4 & 5u;

    EXPECT_EQ(readI32(outAddr + offsetof(Output, sum)), 3);
    EXPECT_EQ(readI32(outAddr + offsetof(Output, min_val)), -4);
    EXPECT_EQ(readI32(outAddr + offsetof(Output, max_val)), 5);
    EXPECT_EQ(readU32(outAddr + offsetof(Output, xor_all)), xor_expected);
    EXPECT_EQ(readU32(outAddr + offsetof(Output, and_masked)), and_expected);
    EXPECT_EQ(readI32(outAddr + offsetof(Output, alternating)), 15);
    EXPECT_EQ(readI32(outAddr + offsetof(Output, dot_self)), 55);
}

// ============================================================
// ExtractValue tests
//
// Struct { i32, i32 } bitvector layout (64-bit, little-endian):
//   bits [ 0,32) = field 0
//   bits [32,64) = field 1
// ============================================================

TEST(ExecutorTest, ExtractValueStructFirstField) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, {i32Ty, i32Ty});

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {structTy}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractValue(fn->getArg(0), {0u}));

    ExecutionStatePtr state = executor.createState();

    // { field0=0x1234, field1=0x5678 } packed little-endian into 64 bits.
    uint64_t agg = (0x5678ULL << 32) | 0x1234ULL;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(agg, Expr::Int64)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x1234u);
}

TEST(ExecutorTest, ExtractValueStructSecondField) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, {i32Ty, i32Ty});

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {structTy}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractValue(fn->getArg(0), {1u}));

    ExecutionStatePtr state = executor.createState();

    // Field 1 is at byte offset 4 → bits [32,64). Expected: 0x5678.
    uint64_t agg = (0x5678ULL << 32) | 0x1234ULL;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(agg, Expr::Int64)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x5678u);
}

TEST(ExecutorTest, ExtractValueArrayElement) {
    llvm::LLVMContext ctx;

    // [4 x i8] bitvector (32-bit): bits [16,24) = element 2.
    auto *i8Ty = llvm::Type::getInt8Ty(ctx);
    auto *arrTy = llvm::ArrayType::get(i8Ty, 4);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i8Ty, {arrTy}, false), llvm::Function::ExternalLinkage,
                                      "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractValue(fn->getArg(0), {2u}));

    ExecutionStatePtr state = executor.createState();

    // [0x01, 0x02, 0x03, 0x04] packed little-endian into 32 bits.
    uint64_t arr = (0x04u << 24) | (0x03u << 16) | (0x02u << 8) | 0x01u;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(arr, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x03u);
}

// ============================================================
// InsertValue tests
//
// Four code paths inside executeInstruction:
//   1. only field  → result = val              (no l, no r)
//   2. first field → result = concat(r, val)   (no l, r exists)
//   3. last field  → result = concat(val, l)   (l exists, no r)
//   4. middle field→ result = concat(r, val, l)(both l and r exist)
// ============================================================

// Path 1: only field – { i32 }. Entire aggregate is replaced.
TEST(ExecutorTest, InsertValueOnlyField) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, llvm::ArrayRef<llvm::Type *>({i32Ty}));

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(structTy, {structTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertValue(fn->getArg(0), fn->getArg(1), {0u}));

    ExecutionStatePtr state = executor.createState();

    auto result = executor.runFunction(
        *state, fn,
        {klee::ConstantExpr::create(0xDEADBEEFu, Expr::Int32), klee::ConstantExpr::create(0xCAFEBABEu, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0xCAFEBABEu);
}

// Path 2: first field of { i32, i32 } – right remainder (field1) preserved.
TEST(ExecutorTest, InsertValueFirstField) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, {i32Ty, i32Ty});

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(structTy, {structTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertValue(fn->getArg(0), fn->getArg(1), {0u}));

    ExecutionStatePtr state = executor.createState();

    // agg = { field0=0xAAAA, field1=0xBBBB }, replace field0 with 0x1234.
    uint64_t agg = (0xBBBBULL << 32) | 0xAAAAULL;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(agg, Expr::Int64), klee::ConstantExpr::create(0x1234u, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), (0xBBBBULL << 32) | 0x1234ULL);
}

// Path 3: last field of { i32, i32 } – left remainder (field0) preserved.
TEST(ExecutorTest, InsertValueLastField) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, {i32Ty, i32Ty});

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(structTy, {structTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertValue(fn->getArg(0), fn->getArg(1), {1u}));

    ExecutionStatePtr state = executor.createState();

    // agg = { field0=0xAAAA, field1=0xBBBB }, replace field1 with 0x5678.
    uint64_t agg = (0xBBBBULL << 32) | 0xAAAAULL;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(agg, Expr::Int64), klee::ConstantExpr::create(0x5678u, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), (0x5678ULL << 32) | 0xAAAAULL);
}

// Path 4: middle field of { i16, i16, i16, i16 } – both left and right remainders exist.
//
// { i16, i16, i16, i16 } bitvector (64-bit, little-endian):
//   bits [ 0,16) = field0, [16,32) = field1, [32,48) = field2, [48,64) = field3
// Insert field1 (byte offset 2): lOffset=16, rOffset=32.
//   l = bits [0,16), r = bits [32,64)
TEST(ExecutorTest, InsertValueMiddleField) {
    llvm::LLVMContext ctx;

    auto *i16Ty = llvm::Type::getInt16Ty(ctx);
    auto *structTy = llvm::StructType::get(ctx, {i16Ty, i16Ty, i16Ty, i16Ty});

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(structTy, {structTy, i16Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertValue(fn->getArg(0), fn->getArg(1), {1u}));

    ExecutionStatePtr state = executor.createState();

    // { 0x1111, 0x2222, 0x3333, 0x4444 } packed little-endian into 64 bits.
    uint64_t agg = (0x4444ULL << 48) | (0x3333ULL << 32) | (0x2222ULL << 16) | 0x1111ULL;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(agg, Expr::Int64), klee::ConstantExpr::create(0xBBBBu, Expr::Int16)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    // field1 replaced, fields 0/2/3 preserved.
    uint64_t expected = (0x4444ULL << 48) | (0x3333ULL << 32) | (0xBBBBULL << 16) | 0x1111ULL;
    EXPECT_EQ(ce->getZExtValue(), expected);
}

// ============================================================
// ExtractElement tests
//
// Vector bitvector layout (little-endian):
//   element i occupies bits [i*EltBits, (i+1)*EltBits)
//
// <2 x i32> [0x1234, 0x5678] packed as a 64-bit integer:
//   bits [ 0,32) = 0x1234  (element 0)
//   bits [32,64) = 0x5678  (element 1)
// ============================================================

// Extract element 0 from <2 x i32> → bits [0,32) = 0x1234.
TEST(ExecutorTest, ExtractElementFirstElement) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i32Ty, 2);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {vecTy}, false), llvm::Function::ExternalLinkage,
                                      "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractElement(fn->getArg(0), b.getInt32(0)));

    ExecutionStatePtr state = executor.createState();

    // <2 x i32> [0x1234, 0x5678] packed little-endian into 64 bits.
    uint64_t vec = (0x5678ULL << 32) | 0x1234ULL;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(vec, Expr::Int64)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x1234u);
}

// Extract element 1 from <2 x i32> → bits [32,64) = 0x5678.
TEST(ExecutorTest, ExtractElementLastElement) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i32Ty, 2);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {vecTy}, false), llvm::Function::ExternalLinkage,
                                      "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractElement(fn->getArg(0), b.getInt32(1)));

    ExecutionStatePtr state = executor.createState();

    // <2 x i32> [0x1234, 0x5678] packed little-endian into 64 bits.
    uint64_t vec = (0x5678ULL << 32) | 0x1234ULL;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(vec, Expr::Int64)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x5678u);
}

// Extract element 2 from <4 x i8> → bits [16,24) = 0x03.
//
// <4 x i8> [0x01, 0x02, 0x03, 0x04] packed as a 32-bit integer:
//   bits [ 0, 8) = 0x01, [8,16) = 0x02, [16,24) = 0x03, [24,32) = 0x04
TEST(ExecutorTest, ExtractElementMiddleElement) {
    llvm::LLVMContext ctx;

    auto *i8Ty = llvm::Type::getInt8Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i8Ty, 4);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i8Ty, {vecTy}, false), llvm::Function::ExternalLinkage,
                                      "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateExtractElement(fn->getArg(0), b.getInt32(2)));

    ExecutionStatePtr state = executor.createState();

    // <4 x i8> [0x01, 0x02, 0x03, 0x04] packed little-endian into 32 bits.
    uint32_t vec = (0x04u << 24) | (0x03u << 16) | (0x02u << 8) | 0x01u;
    auto result = executor.runFunction(*state, fn, {klee::ConstantExpr::create(vec, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0x03u);
}

// ============================================================
// InsertElement tests
//
// Four code paths (mirroring InsertValue, but over vector lanes):
//   1. single-element vector → result = newElt
//   2. first element         → l absent, r = remaining high lanes
//   3. last element          → l = remaining low lanes, r absent
//   4. middle element        → both l and r exist
// ============================================================

// Path 1: single-element <1 x i32>. Entire vector is replaced.
TEST(ExecutorTest, InsertElementOnlyElement) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i32Ty, 1);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(vecTy, {vecTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertElement(fn->getArg(0), fn->getArg(1), b.getInt32(0)));

    ExecutionStatePtr state = executor.createState();

    auto result = executor.runFunction(
        *state, fn,
        {klee::ConstantExpr::create(0xDEADBEEFu, Expr::Int32), klee::ConstantExpr::create(0xCAFEBABEu, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 0xCAFEBABEu);
}

// Path 2: insert element 0 of <2 x i32> – high lane (element 1) preserved.
TEST(ExecutorTest, InsertElementFirstElement) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i32Ty, 2);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(vecTy, {vecTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertElement(fn->getArg(0), fn->getArg(1), b.getInt32(0)));

    ExecutionStatePtr state = executor.createState();

    // vec = [0xAAAA, 0xBBBB]; replace element 0 with 0x1234.
    uint64_t vec = (0xBBBBULL << 32) | 0xAAAAULL;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(vec, Expr::Int64), klee::ConstantExpr::create(0x1234u, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), (0xBBBBULL << 32) | 0x1234ULL);
}

// Path 3: insert element 1 of <2 x i32> – low lane (element 0) preserved.
TEST(ExecutorTest, InsertElementLastElement) {
    llvm::LLVMContext ctx;

    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i32Ty, 2);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(vecTy, {vecTy, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertElement(fn->getArg(0), fn->getArg(1), b.getInt32(1)));

    ExecutionStatePtr state = executor.createState();

    // vec = [0xAAAA, 0xBBBB]; replace element 1 with 0x5678.
    uint64_t vec = (0xBBBBULL << 32) | 0xAAAAULL;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(vec, Expr::Int64), klee::ConstantExpr::create(0x5678u, Expr::Int32)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), (0x5678ULL << 32) | 0xAAAAULL);
}

// Path 4: insert element 2 of <4 x i8> – lanes 0/1 (l) and lane 3 (r) preserved.
//
// <4 x i8> [0x01, 0x02, 0x03, 0x04] packed as 32-bit little-endian integer.
// Replace element 2 (bits [16,24)) with 0xFF.
TEST(ExecutorTest, InsertElementMiddleElement) {
    llvm::LLVMContext ctx;

    auto *i8Ty = llvm::Type::getInt8Ty(ctx);
    auto *vecTy = llvm::FixedVectorType::get(i8Ty, 4);

    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(vecTy, {vecTy, i8Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateInsertElement(fn->getArg(0), fn->getArg(1), b.getInt32(2)));

    ExecutionStatePtr state = executor.createState();

    // vec = [0x01, 0x02, 0x03, 0x04]; replace element 2 with 0xFF.
    uint32_t vec = (0x04u << 24) | (0x03u << 16) | (0x02u << 8) | 0x01u;
    auto result = executor.runFunction(
        *state, fn, {klee::ConstantExpr::create(vec, Expr::Int32), klee::ConstantExpr::create(0xFFu, Expr::Int8)});

    ASSERT_NE(result.get(), nullptr);
    auto *ce = dyn_cast<klee::ConstantExpr>(result);
    ASSERT_NE(ce, nullptr);
    // Elements 0/1/3 unchanged; element 2 = 0xFF.
    uint32_t expected = (0x04u << 24) | (0xFFu << 16) | (0x02u << 8) | 0x01u;
    EXPECT_EQ(ce->getZExtValue(), expected);
}

// ============================================================
// function.bc tests: call, switch, trunc, ptr conversions
// ============================================================

// ── helper ──────────────────────────────────────────────────
// Load function.bc once per test, look up a named function, run it with
// one i32 argument, and return the i32 result.
static uint64_t evalFunctionI32(const char *name, uint32_t arg) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, FUNCTION_BC_PATH);
    llvm::Function *fn = executor.getLLVMModule()->getFunction(name);
    assert(fn && "function not found in function.bc");
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(arg, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

// ── call + return ────────────────────────────────────────────
// call_chain(x) = double_it(x) + 1 = 2*x + 1
TEST(ExecutorTest, FunctionCallChain) {
    EXPECT_EQ(evalFunctionI32("call_chain", 5), 11u);                           // 2*5 + 1
    EXPECT_EQ(evalFunctionI32("call_chain", 0), 1u);                            // 2*0 + 1
    EXPECT_EQ(evalFunctionI32("call_chain", -1u), (uint64_t) (uint32_t) (-1u)); // wraps
}

// ── switch ───────────────────────────────────────────────────
// classify: 0→10, 1→20, 2→30, else→-1
TEST(ExecutorTest, SwitchStatement) {
    EXPECT_EQ(evalFunctionI32("classify", 0), 10u);
    EXPECT_EQ(evalFunctionI32("classify", 1), 20u);
    EXPECT_EQ(evalFunctionI32("classify", 2), 30u);
    EXPECT_EQ(evalFunctionI32("classify", 99), 0xFFFFFFFFu); // -1 zero-extended
}

// ── truncation ───────────────────────────────────────────────
// Trunc drops high bits: only the low N bits survive.
TEST(ExecutorTest, TruncToU8) {
    EXPECT_EQ(evalFunctionI32("trunc_to_u8", 0x12345678u), 0x78u);
    EXPECT_EQ(evalFunctionI32("trunc_to_u8", 0x00000100u), 0x00u); // high byte only
}

TEST(ExecutorTest, TruncToU16) {
    EXPECT_EQ(evalFunctionI32("trunc_to_u16", 0x12345678u), 0x5678u);
    EXPECT_EQ(evalFunctionI32("trunc_to_u16", 0xFFFF0000u), 0x0000u);
}

// ── pointer conversions ──────────────────────────────────────
// PtrToInt: the pointer value passes through as an integer of pointer width.
TEST(ExecutorTest, PtrToInt) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, FUNCTION_BC_PATH);
    llvm::Function *fn = executor.getLLVMModule()->getFunction("ptr_to_int");
    ASSERT_NE(fn, nullptr);

    unsigned ptrWidth = executor.getModule()->getDataLayout()->getPointerSizeInBits();
    constexpr uint64_t fakePtr = 0xDEADBEEFCAFE0000ULL;

    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(fakePtr, ptrWidth)});
    auto *ce = dyn_cast<klee::ConstantExpr>(r);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), fakePtr);
}

// IntToPtr: the integer value passes through as a pointer-width expression.
TEST(ExecutorTest, IntToPtr) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, FUNCTION_BC_PATH);
    llvm::Function *fn = executor.getLLVMModule()->getFunction("int_to_ptr");
    ASSERT_NE(fn, nullptr);

    unsigned ptrWidth = executor.getModule()->getDataLayout()->getPointerSizeInBits();
    constexpr uint64_t fakeAddr = 0x00007FFF12345678ULL;

    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(fakeAddr, Expr::Int64)});
    auto *ce = dyn_cast<klee::ConstantExpr>(r);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), fakeAddr);
    EXPECT_EQ(ce->getWidth(), ptrWidth);
}

// ── function pointer (indirect call) ────────────────────────
//
// apply(fn, x) calls fn(x) through a non-constant SSA value, which forces
// the executor down the indirect-call path (getTargetFunction returns null).
// The executor evaluates the concrete pointer, creates an external stub via
// DynamicLibrary::AddSymbol, and dispatches the call natively.
//
// native_triple (defined above the anonymous namespace with C linkage) is a
// real callable function; passing its host address as the fn argument gives
// the external dispatcher a valid target to call.
TEST(ExecutorTest, FunctionPointerIndirectCall) {
    llvm::LLVMContext ctx;
    TestExecutor executor(ctx, FUNCTION_BC_PATH);
    llvm::Function *fn = executor.getLLVMModule()->getFunction("apply");
    ASSERT_NE(fn, nullptr);

    unsigned ptrWidth = executor.getModule()->getDataLayout()->getPointerSizeInBits();

    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn,
                                  {klee::ConstantExpr::create((uint64_t) (void *) native_triple, ptrWidth),
                                   klee::ConstantExpr::create(7u, Expr::Int32)});
    auto *ce = dyn_cast<klee::ConstantExpr>(r);
    ASSERT_NE(ce, nullptr);
    EXPECT_EQ(ce->getZExtValue(), 21u); // native_triple(7) = 3*7 = 21
}

// ============================================================
// Arithmetic and logic binary-op tests
//
// SDiv/SRem use -7 (= 0xFFFFFFF9) to verify signed semantics diverge
// from unsigned: -7 /u 2 = 0x7FFFFFFC, -7 /s 2 = -3 = 0xFFFFFFFD.
// AShr uses 0x80000008 to verify sign-extension: logical shift gives
// 0x40000004, arithmetic shift gives 0xC0000004.
// ============================================================

/// Build `i32 f(i32 %a, i32 %b) { ret i32 (op %a, %b) }`, run it with
/// concrete operands, and return the i32 result.
static uint64_t evalBinop(llvm::Instruction::BinaryOps op, uint32_t a, uint32_t b) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {i32Ty, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateBinOp(op, fn->getArg(0), fn->getArg(1)));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(
        *s, fn, {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

TEST(ExecutorTest, Add) {
    EXPECT_EQ(evalBinop(Instruction::Add, 5, 3), 8u);
    EXPECT_EQ(evalBinop(Instruction::Add, 0xFFFFFFFFu, 1), 0u); // wraps
}

TEST(ExecutorTest, Sub) {
    EXPECT_EQ(evalBinop(Instruction::Sub, 5, 3), 2u);
    EXPECT_EQ(evalBinop(Instruction::Sub, 0u, 1u), 0xFFFFFFFFu); // wraps
}

TEST(ExecutorTest, Mul) {
    EXPECT_EQ(evalBinop(Instruction::Mul, 6, 7), 42u);
    EXPECT_EQ(evalBinop(Instruction::Mul, 0x80000000u, 2), 0u); // wraps
}

TEST(ExecutorTest, UDiv) {
    EXPECT_EQ(evalBinop(Instruction::UDiv, 7, 2), 3u);
    // 0xFFFFFFF9 (= -7 as signed) /u 2 = 0x7FFFFFFCu  (unsigned semantics)
    EXPECT_EQ(evalBinop(Instruction::UDiv, 0xFFFFFFF9u, 2), 0x7FFFFFFCu);
}

TEST(ExecutorTest, SDiv) {
    EXPECT_EQ(evalBinop(Instruction::SDiv, 7, 2), 3u);
    // -7 /s 2 = -3 = 0xFFFFFFFD  (signed semantics, truncates toward zero)
    EXPECT_EQ(evalBinop(Instruction::SDiv, 0xFFFFFFF9u, 2), 0xFFFFFFFDu);
}

TEST(ExecutorTest, URem) {
    EXPECT_EQ(evalBinop(Instruction::URem, 7, 3), 1u);
    // 0xFFFFFFF9u % 3 = 0xFFFFFFF9u - 3*(0xFFFFFFF9u/3)
    EXPECT_EQ(evalBinop(Instruction::URem, 0xFFFFFFF9u, 3), 0xFFFFFFF9u % 3u);
}

TEST(ExecutorTest, SRem) {
    EXPECT_EQ(evalBinop(Instruction::SRem, 7, 3), 1u);
    // -7 %s 3 = -1 = 0xFFFFFFFF  (sign follows dividend)
    EXPECT_EQ(evalBinop(Instruction::SRem, 0xFFFFFFF9u, 3), 0xFFFFFFFFu);
}

TEST(ExecutorTest, And) {
    EXPECT_EQ(evalBinop(Instruction::And, 0xF0F0F0F0u, 0x0F0F0F0Fu), 0u);
    EXPECT_EQ(evalBinop(Instruction::And, 0xFFFF0000u, 0xFFFFFFFFu), 0xFFFF0000u);
}

TEST(ExecutorTest, Or) {
    EXPECT_EQ(evalBinop(Instruction::Or, 0xF0F0F0F0u, 0x0F0F0F0Fu), 0xFFFFFFFFu);
    EXPECT_EQ(evalBinop(Instruction::Or, 0u, 0u), 0u);
}

TEST(ExecutorTest, Xor) {
    EXPECT_EQ(evalBinop(Instruction::Xor, 0xFFFFFFFFu, 0xFFFFFFFFu), 0u);
    EXPECT_EQ(evalBinop(Instruction::Xor, 0xF0F0F0F0u, 0x0F0F0F0Fu), 0xFFFFFFFFu);
}

TEST(ExecutorTest, Shl) {
    EXPECT_EQ(evalBinop(Instruction::Shl, 1, 4), 16u);
    EXPECT_EQ(evalBinop(Instruction::Shl, 0xFFFFFFFFu, 1), 0xFFFFFFFEu); // high bit shifted out
}

TEST(ExecutorTest, LShr) {
    EXPECT_EQ(evalBinop(Instruction::LShr, 0x80000008u, 1), 0x40000004u); // zero-fills high bit
    EXPECT_EQ(evalBinop(Instruction::LShr, 16, 4), 1u);
}

TEST(ExecutorTest, AShr) {
    EXPECT_EQ(evalBinop(Instruction::AShr, 0x80000008u, 1), 0xC0000004u); // sign-extends high bit
    EXPECT_EQ(evalBinop(Instruction::AShr, 16, 4), 1u);                   // positive: same as LShr
}

// ============================================================
// Floating-point instruction tests
//
// All operations use f32 (32 bits) unless the instruction requires two
// precisions (FPTrunc: f64→f32, FPExt: f32→f64).
//
// Key bit patterns (IEEE 754):
//   f32:  1.0=0x3F800000  1.5=0x3FC00000  2.0=0x40000000
//         3.0=0x40400000  3.5=0x40600000  -2.0=0xC0000000
//         qNaN=0x7FC00000
//   f64:  3.0=0x4008000000000000
//
// FCmp predicates are exercised in ordered/unordered pairs; a NaN operand
// distinguishes the two (O* returns false when NaN is present; U* returns true).
// ============================================================

/// Build `f32 f(f32, f32) { ret op(%a, %b) }` and run with f32 bit patterns.
static uint32_t evalFBinop(llvm::Instruction::BinaryOps op, uint32_t a, uint32_t b) {
    llvm::LLVMContext ctx;
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(f32Ty, {f32Ty, f32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateBinOp(op, fn->getArg(0), fn->getArg(1)));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(
        *s, fn, {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// Build `i1 f(f32, f32) { ret fcmp <pred> %a, %b }` and run with f32 bit patterns.
static uint64_t evalFCmp(llvm::FCmpInst::Predicate pred, uint32_t a, uint32_t b) {
    llvm::LLVMContext ctx;
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt1Ty(ctx), {f32Ty, f32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateFCmp(pred, fn->getArg(0), fn->getArg(1)));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(
        *s, fn, {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// FPTrunc: f64 → f32 (narrowing conversion).
static uint32_t evalFPTrunc(uint64_t f64bits) {
    llvm::LLVMContext ctx;
    auto *f64Ty = llvm::Type::getDoubleTy(ctx), *f32Ty = llvm::Type::getFloatTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(f32Ty, {f64Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateFPTrunc(fn->getArg(0), f32Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(f64bits, Expr::Int64)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// FPExt: f32 → f64 (widening conversion).
static uint64_t evalFPExt(uint32_t f32bits) {
    llvm::LLVMContext ctx;
    auto *f32Ty = llvm::Type::getFloatTy(ctx), *f64Ty = llvm::Type::getDoubleTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(f64Ty, {f32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateFPExt(fn->getArg(0), f64Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(f32bits, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// FPToUI: f32 → u32 (truncation toward zero).
static uint32_t evalFPToUI(uint32_t f32bits) {
    llvm::LLVMContext ctx;
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {f32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateFPToUI(fn->getArg(0), i32Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(f32bits, Expr::Int32)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// FPToSI: f32 → i32 (truncation toward zero, signed).
static uint32_t evalFPToSI(uint32_t f32bits) {
    llvm::LLVMContext ctx;
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {f32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateFPToSI(fn->getArg(0), i32Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(f32bits, Expr::Int32)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// UIToFP: u32 → f32.
static uint32_t evalUIToFP(uint32_t val) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(f32Ty, {i32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateUIToFP(fn->getArg(0), f32Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(val, Expr::Int32)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// SIToFP: i32 → f32.
static uint32_t evalSIToFP(uint32_t val) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    auto *f32Ty = llvm::Type::getFloatTy(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(f32Ty, {i32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateSIToFP(fn->getArg(0), f32Ty));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(val, Expr::Int32)});
    return (uint32_t) dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

// ── binary arithmetic ────────────────────────────────────────

TEST(ExecutorTest, FAdd) {
    EXPECT_EQ(evalFBinop(Instruction::FAdd, 0x3F800000u, 0x40000000u), 0x40400000u); // 1+2=3
    EXPECT_EQ(evalFBinop(Instruction::FAdd, 0x00000000u, 0x3F800000u), 0x3F800000u); // 0+1=1
}

TEST(ExecutorTest, FSub) {
    EXPECT_EQ(evalFBinop(Instruction::FSub, 0x40400000u, 0x3F800000u), 0x40000000u); // 3-1=2
    EXPECT_EQ(evalFBinop(Instruction::FSub, 0x3F800000u, 0x3F800000u), 0x00000000u); // 1-1=0
}

TEST(ExecutorTest, FMul) {
    EXPECT_EQ(evalFBinop(Instruction::FMul, 0x40000000u, 0x3FC00000u), 0x40400000u); // 2*1.5=3
    EXPECT_EQ(evalFBinop(Instruction::FMul, 0x3F800000u, 0x00000000u), 0x00000000u); // 1*0=0
}

TEST(ExecutorTest, FDiv) {
    EXPECT_EQ(evalFBinop(Instruction::FDiv, 0x40400000u, 0x40000000u), 0x3FC00000u); // 3/2=1.5
    EXPECT_EQ(evalFBinop(Instruction::FDiv, 0x3F800000u, 0x3F800000u), 0x3F800000u); // 1/1=1
}

TEST(ExecutorTest, FRem) {
    EXPECT_EQ(evalFBinop(Instruction::FRem, 0x40600000u, 0x40000000u), 0x3FC00000u); // 3.5%2=1.5
    EXPECT_EQ(evalFBinop(Instruction::FRem, 0x40000000u, 0x3F800000u), 0x00000000u); // 2%1=0
}

// ── conversions ──────────────────────────────────────────────

TEST(ExecutorTest, FPTrunc) {
    // 3.0 (f64=0x4008000000000000) → 3.0f (f32=0x40400000)
    EXPECT_EQ(evalFPTrunc(0x4008000000000000ULL), 0x40400000u);
    // 1.0 (f64=0x3FF0000000000000) → 1.0f (f32=0x3F800000)
    EXPECT_EQ(evalFPTrunc(0x3FF0000000000000ULL), 0x3F800000u);
}

TEST(ExecutorTest, FPExt) {
    // 3.0f → 3.0
    EXPECT_EQ(evalFPExt(0x40400000u), 0x4008000000000000ULL);
    // 1.0f → 1.0
    EXPECT_EQ(evalFPExt(0x3F800000u), 0x3FF0000000000000ULL);
}

TEST(ExecutorTest, FPToUI) {
    EXPECT_EQ(evalFPToUI(0x40400000u), 3u); // 3.0f → 3
    EXPECT_EQ(evalFPToUI(0x00000000u), 0u); // 0.0f → 0
}

TEST(ExecutorTest, FPToSI) {
    EXPECT_EQ(evalFPToSI(0x40400000u), 3u);          // 3.0f  → 3
    EXPECT_EQ(evalFPToSI(0xC0000000u), 0xFFFFFFFEu); // -2.0f → -2
}

TEST(ExecutorTest, UIToFP) {
    EXPECT_EQ(evalUIToFP(3u), 0x40400000u); // 3 → 3.0f
    EXPECT_EQ(evalUIToFP(0u), 0x00000000u); // 0 → 0.0f
}

TEST(ExecutorTest, SIToFP) {
    EXPECT_EQ(evalSIToFP(3u), 0x40400000u);          // 3  → 3.0f
    EXPECT_EQ(evalSIToFP(0xFFFFFFFEu), 0xC0000000u); // -2 → -2.0f
}

// ── FCmp predicates ──────────────────────────────────────────
//
// Operand constants:
//   lo = 1.0f = 0x3F800000
//   hi = 2.0f = 0x40000000
//   nan = quiet NaN = 0x7FC00000
//
// Each test covers the ordered (O*) and unordered (U*) twin predicates.
// The NaN case is always included because that is the only input that
// distinguishes O* (returns false) from U* (returns true).

static constexpr uint32_t kFCmpLo = 0x3F800000u;  // 1.0f
static constexpr uint32_t kFCmpHi = 0x40000000u;  // 2.0f
static constexpr uint32_t kFCmpNaN = 0x7FC00000u; // quiet NaN

TEST(ExecutorTest, FCmpFalseTrue) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_FALSE, kFCmpLo, kFCmpHi), 0u); // always false
    EXPECT_EQ(evalFCmp(P::FCMP_FALSE, kFCmpLo, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_FALSE, kFCmpNaN, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_TRUE, kFCmpLo, kFCmpHi), 1u); // always true
    EXPECT_EQ(evalFCmp(P::FCMP_TRUE, kFCmpLo, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_TRUE, kFCmpNaN, kFCmpLo), 1u);
}

TEST(ExecutorTest, FCmpOrdUno) {
    using P = llvm::FCmpInst;
    // ORD: true iff neither operand is NaN
    EXPECT_EQ(evalFCmp(P::FCMP_ORD, kFCmpLo, kFCmpHi), 1u);  // no NaN
    EXPECT_EQ(evalFCmp(P::FCMP_ORD, kFCmpNaN, kFCmpLo), 0u); // NaN present
    // UNO: true iff at least one operand is NaN
    EXPECT_EQ(evalFCmp(P::FCMP_UNO, kFCmpLo, kFCmpHi), 0u);  // no NaN
    EXPECT_EQ(evalFCmp(P::FCMP_UNO, kFCmpNaN, kFCmpLo), 1u); // NaN present
}

TEST(ExecutorTest, FCmpOeqUeq) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_OEQ, kFCmpLo, kFCmpLo), 1u);  // equal, ordered
    EXPECT_EQ(evalFCmp(P::FCMP_OEQ, kFCmpLo, kFCmpHi), 0u);  // unequal
    EXPECT_EQ(evalFCmp(P::FCMP_OEQ, kFCmpNaN, kFCmpLo), 0u); // NaN → false
    EXPECT_EQ(evalFCmp(P::FCMP_UEQ, kFCmpLo, kFCmpLo), 1u);  // equal
    EXPECT_EQ(evalFCmp(P::FCMP_UEQ, kFCmpLo, kFCmpHi), 0u);  // unequal, ordered
    EXPECT_EQ(evalFCmp(P::FCMP_UEQ, kFCmpNaN, kFCmpLo), 1u); // NaN → true
}

TEST(ExecutorTest, FCmpOgtUgt) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_OGT, kFCmpHi, kFCmpLo), 1u);  // 2 > 1
    EXPECT_EQ(evalFCmp(P::FCMP_OGT, kFCmpLo, kFCmpHi), 0u);  // 1 > 2 → false
    EXPECT_EQ(evalFCmp(P::FCMP_OGT, kFCmpLo, kFCmpLo), 0u);  // equal → false
    EXPECT_EQ(evalFCmp(P::FCMP_OGT, kFCmpNaN, kFCmpLo), 0u); // NaN → false
    EXPECT_EQ(evalFCmp(P::FCMP_UGT, kFCmpHi, kFCmpLo), 1u);  // 2 > 1
    EXPECT_EQ(evalFCmp(P::FCMP_UGT, kFCmpLo, kFCmpHi), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_UGT, kFCmpNaN, kFCmpLo), 1u); // NaN → true
}

TEST(ExecutorTest, FCmpOgeUge) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_OGE, kFCmpHi, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_OGE, kFCmpLo, kFCmpLo), 1u); // equal counts
    EXPECT_EQ(evalFCmp(P::FCMP_OGE, kFCmpLo, kFCmpHi), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_OGE, kFCmpNaN, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_UGE, kFCmpHi, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_UGE, kFCmpLo, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_UGE, kFCmpLo, kFCmpHi), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_UGE, kFCmpNaN, kFCmpLo), 1u);
}

TEST(ExecutorTest, FCmpOltUlt) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_OLT, kFCmpLo, kFCmpHi), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLT, kFCmpHi, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLT, kFCmpLo, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLT, kFCmpNaN, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULT, kFCmpLo, kFCmpHi), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULT, kFCmpHi, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULT, kFCmpNaN, kFCmpLo), 1u);
}

TEST(ExecutorTest, FCmpOleUle) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_OLE, kFCmpLo, kFCmpHi), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLE, kFCmpLo, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLE, kFCmpHi, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_OLE, kFCmpNaN, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULE, kFCmpLo, kFCmpHi), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULE, kFCmpLo, kFCmpLo), 1u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULE, kFCmpHi, kFCmpLo), 0u);
    EXPECT_EQ(evalFCmp(P::FCMP_ULE, kFCmpNaN, kFCmpLo), 1u);
}

TEST(ExecutorTest, FCmpOneUne) {
    using P = llvm::FCmpInst;
    EXPECT_EQ(evalFCmp(P::FCMP_ONE, kFCmpLo, kFCmpHi), 1u);  // ordered not-equal
    EXPECT_EQ(evalFCmp(P::FCMP_ONE, kFCmpLo, kFCmpLo), 0u);  // equal → false
    EXPECT_EQ(evalFCmp(P::FCMP_ONE, kFCmpNaN, kFCmpLo), 0u); // NaN → false (not ordered)
    EXPECT_EQ(evalFCmp(P::FCMP_UNE, kFCmpLo, kFCmpHi), 1u);  // unordered not-equal
    EXPECT_EQ(evalFCmp(P::FCMP_UNE, kFCmpLo, kFCmpLo), 0u);  // equal → false
    EXPECT_EQ(evalFCmp(P::FCMP_UNE, kFCmpNaN, kFCmpLo), 1u); // NaN → true
}

// ============================================================
// Intrinsic tests
//
// Covered: llvm.fabs (f32/f64), llvm.abs (i32), llvm.smax, llvm.smin,
//          llvm.umax, llvm.umin, llvm.fshl, llvm.fshr.
// Skipped: llvm.vastart / llvm.vaend (require a varargs function setup).
//
// Float values are passed and returned as their IEEE 754 bit patterns:
//   -3.0f = 0xC0400000,  3.0f = 0x40400000,  -0.0f = 0x80000000
//   -1.0  = 0xBFF0000000000000, 1.0 = 0x3FF0000000000000
//
// fshl(a, b, amt): concat [a:b] (a in high bits), shift left  by amt%w, take high w bits.
// fshr(a, b, amt): concat [a:b] (a in high bits), shift right by amt%w, take low  w bits.
// ============================================================

/// Build `i32 f(i32) { ret llvm.abs.i32(arg, <poison>) }` and run it.
static uint64_t evalAbs(uint32_t x, bool poison) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *intrFn = llvm::Intrinsic::getDeclaration(mod, llvm::Intrinsic::abs, {i32Ty});
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {i32Ty}, false), llvm::Function::ExternalLinkage,
                                      "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateCall(intrFn, {fn->getArg(0), llvm::ConstantInt::get(llvm::Type::getInt1Ty(ctx), poison)}));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(x, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// Build `i32 f(i32, i32) { ret llvm.<id>.i32(a, b) }` for smax/smin/umax/umin and run it.
static uint64_t evalMinMax(llvm::Intrinsic::ID id, uint32_t a, uint32_t b) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *intrFn = llvm::Intrinsic::getDeclaration(mod, id, {i32Ty});
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {i32Ty, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateCall(intrFn, {fn->getArg(0), fn->getArg(1)}));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(
        *s, fn, {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// Build `i32 f(i32, i32, i32) { ret llvm.<id>.i32(a, b, amt) }` for fshl/fshr and run it.
static uint64_t evalFunnel(llvm::Intrinsic::ID id, uint32_t a, uint32_t b, uint32_t amt) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *intrFn = llvm::Intrinsic::getDeclaration(mod, id, {i32Ty});
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(i32Ty, {i32Ty, i32Ty, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateCall(intrFn, {fn->getArg(0), fn->getArg(1), fn->getArg(2)}));
    ExecutionStatePtr s = executor.createState();
    auto r =
        executor.runFunction(*s, fn,
                             {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32),
                              klee::ConstantExpr::create(amt, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

/// Build `fN f(fN) { ret llvm.fabs.fN(arg) }` and run it with the given bit pattern.
/// width must be 32 (float) or 64 (double).
static uint64_t evalFabs(unsigned width, uint64_t bits) {
    llvm::LLVMContext ctx;
    llvm::Type *fTy = width == 32 ? llvm::Type::getFloatTy(ctx) : llvm::Type::getDoubleTy(ctx);
    TestExecutor executor(ctx);
    auto *mod = executor.getLLVMModule();
    auto *intrFn = llvm::Intrinsic::getDeclaration(mod, llvm::Intrinsic::fabs, {fTy});
    auto *fn =
        llvm::Function::Create(llvm::FunctionType::get(fTy, {fTy}, false), llvm::Function::ExternalLinkage, "f", mod);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(ctx, "entry", fn));
    b.CreateRet(b.CreateCall(intrFn, {fn->getArg(0)}));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(*s, fn, {klee::ConstantExpr::create(bits, width)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

// fabs f32: negative → positive; positive unchanged; -0.0 → 0.0.
TEST(ExecutorTest, IntrinsicFabsF32) {
    EXPECT_EQ(evalFabs(32, 0xC0400000u), 0x40400000u); // -3.0f → 3.0f
    EXPECT_EQ(evalFabs(32, 0x40400000u), 0x40400000u); //  3.0f unchanged
    EXPECT_EQ(evalFabs(32, 0x80000000u), 0x00000000u); // -0.0f → 0.0f
}

// fabs f64: same semantics as f32 but 64-bit.
TEST(ExecutorTest, IntrinsicFabsF64) {
    EXPECT_EQ(evalFabs(64, 0xBFF0000000000000ULL), 0x3FF0000000000000ULL); // -1.0 → 1.0
    EXPECT_EQ(evalFabs(64, 0x3FF0000000000000ULL), 0x3FF0000000000000ULL); //  1.0 unchanged
    EXPECT_EQ(evalFabs(64, 0x8000000000000000ULL), 0x0000000000000000ULL); // -0.0 → 0.0
}

// abs i32: positive unchanged; negative flipped; INT_MIN with poison=false stays as INT_MIN.
TEST(ExecutorTest, IntrinsicAbs) {
    EXPECT_EQ(evalAbs(5, false), 5u);
    EXPECT_EQ(evalAbs((uint32_t) -3, false), 3u);
    EXPECT_EQ(evalAbs(0, false), 0u);
    // abs(INT_MIN, poison=false): notsmin=false → cond=false → result = op = INT_MIN
    EXPECT_EQ(evalAbs(0x80000000u, false), 0x80000000u);
}

// smax: signed greatest of two i32s (-1 = 0xFFFFFFFF is less than 1 in signed).
TEST(ExecutorTest, IntrinsicSmax) {
    EXPECT_EQ(evalMinMax(Intrinsic::smax, 5, 3), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::smax, 3, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::smax, 5, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::smax, 1, 0xFFFFFFFFu), 1u); // 1 >s -1
    EXPECT_EQ(evalMinMax(Intrinsic::smax, 0xFFFFFFFFu, 1), 1u);
}

// smin: signed least of two i32s.
TEST(ExecutorTest, IntrinsicSmin) {
    EXPECT_EQ(evalMinMax(Intrinsic::smin, 5, 3), 3u);
    EXPECT_EQ(evalMinMax(Intrinsic::smin, 3, 5), 3u);
    EXPECT_EQ(evalMinMax(Intrinsic::smin, 5, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::smin, 0xFFFFFFFFu, 1), 0xFFFFFFFFu); // -1 <s 1
    EXPECT_EQ(evalMinMax(Intrinsic::smin, 1, 0xFFFFFFFFu), 0xFFFFFFFFu);
}

// umax: unsigned greatest (0xFFFFFFFF >u 1, opposite of signed).
TEST(ExecutorTest, IntrinsicUmax) {
    EXPECT_EQ(evalMinMax(Intrinsic::umax, 5, 3), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::umax, 3, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::umax, 5, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::umax, 0xFFFFFFFFu, 1), 0xFFFFFFFFu); // 0xFFFF… >u 1
    EXPECT_EQ(evalMinMax(Intrinsic::umax, 1, 0xFFFFFFFFu), 0xFFFFFFFFu);
}

// umin: unsigned least.
TEST(ExecutorTest, IntrinsicUmin) {
    EXPECT_EQ(evalMinMax(Intrinsic::umin, 5, 3), 3u);
    EXPECT_EQ(evalMinMax(Intrinsic::umin, 3, 5), 3u);
    EXPECT_EQ(evalMinMax(Intrinsic::umin, 5, 5), 5u);
    EXPECT_EQ(evalMinMax(Intrinsic::umin, 0xFFFFFFFFu, 1), 1u); // 1 <u 0xFFFF…
    EXPECT_EQ(evalMinMax(Intrinsic::umin, 1, 0xFFFFFFFFu), 1u);
}

// fshl(a, b, amt): concat [a:b], shift left by amt%32, return high 32 bits.
TEST(ExecutorTest, IntrinsicFshl) {
    // concat=0x12345678_ABCDEF00, <<8 → hi32=0x345678AB
    EXPECT_EQ(evalFunnel(Intrinsic::fshl, 0x12345678u, 0xABCDEF00u, 8), 0x345678ABu);
    // shift by 0: hi32 = a (unchanged)
    EXPECT_EQ(evalFunnel(Intrinsic::fshl, 0xAAAAAAAAu, 0xBBBBBBBBu, 0), 0xAAAAAAAAu);
    // shift by 32 ≡ 0 mod 32: same as shift by 0
    EXPECT_EQ(evalFunnel(Intrinsic::fshl, 0xAAAAAAAAu, 0xBBBBBBBBu, 32), 0xAAAAAAAAu);
    // shift by 1: high bit of b feeds into low bit of result
    // concat=0x00000001_80000000, <<1 → 0x00000003_00000000, hi32=0x00000003
    EXPECT_EQ(evalFunnel(Intrinsic::fshl, 0x00000001u, 0x80000000u, 1), 0x00000003u);
}

// fshr(a, b, amt): concat [a:b], shift right by amt%32, return low 32 bits.
TEST(ExecutorTest, IntrinsicFshr) {
    // concat=0x12345678_ABCDEF00, >>8 → lo32=0x78ABCDEF
    EXPECT_EQ(evalFunnel(Intrinsic::fshr, 0x12345678u, 0xABCDEF00u, 8), 0x78ABCDEFu);
    // shift by 0: lo32 = b (unchanged)
    EXPECT_EQ(evalFunnel(Intrinsic::fshr, 0xAAAAAAAAu, 0xBBBBBBBBu, 0), 0xBBBBBBBBu);
    // shift by 32 ≡ 0 mod 32: same as shift by 0
    EXPECT_EQ(evalFunnel(Intrinsic::fshr, 0xAAAAAAAAu, 0xBBBBBBBBu, 32), 0xBBBBBBBBu);
    // shift by 1: low bit of a feeds into high bit of result
    // concat=0x00000001_00000000, >>1 → 0x00000000_80000000, lo32=0x80000000
    EXPECT_EQ(evalFunnel(Intrinsic::fshr, 0x00000001u, 0x00000000u, 1), 0x80000000u);
}

// ============================================================
// ICmp tests
//
// Signed-comparison cases use -1 (= 0xFFFFFFFF) to verify that signed
// and unsigned orderings diverge: 0xFFFFFFFF >u 1 but -1 <s 1.
// ============================================================

/// Build `i1 f(i32 %a, i32 %b) { ret i1 (icmp <pred> %a, %b) }`, execute it
/// with concrete operands, and return the 1-bit result as 0 or 1.
static uint64_t evalICmp(llvm::CmpInst::Predicate pred, uint32_t a, uint32_t b) {
    llvm::LLVMContext ctx;
    auto *i32Ty = llvm::Type::getInt32Ty(ctx);
    TestExecutor executor(ctx);
    auto *fn = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt1Ty(ctx), {i32Ty, i32Ty}, false),
                                      llvm::Function::ExternalLinkage, "f", executor.getLLVMModule());
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(ctx, "entry", fn));
    builder.CreateRet(builder.CreateICmp(pred, fn->getArg(0), fn->getArg(1)));
    ExecutionStatePtr s = executor.createState();
    auto r = executor.runFunction(
        *s, fn, {klee::ConstantExpr::create(a, Expr::Int32), klee::ConstantExpr::create(b, Expr::Int32)});
    return dyn_cast<klee::ConstantExpr>(r)->getZExtValue();
}

TEST(ExecutorTest, ICmpEQ) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_EQ, 5, 5), 1u); // equal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_EQ, 5, 3), 0u); // unequal → false
}

TEST(ExecutorTest, ICmpNE) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_NE, 5, 3), 1u); // unequal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_NE, 5, 5), 0u); // equal → false
}

TEST(ExecutorTest, ICmpUGT) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGT, 5, 3), 1u);           // 5 >u 3 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGT, 3, 5), 0u);           // 3 >u 5 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGT, 5, 5), 0u);           // equal → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGT, 0xFFFFFFFFu, 1), 1u); // 0xFFFF… >u 1 → true (differs from signed)
}

TEST(ExecutorTest, ICmpUGE) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGE, 5, 3), 1u); // 5 >=u 3 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGE, 5, 5), 1u); // equal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_UGE, 3, 5), 0u); // 3 >=u 5 → false
}

TEST(ExecutorTest, ICmpULT) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULT, 3, 5), 1u);           // 3 <u 5 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULT, 5, 3), 0u);           // 5 <u 3 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULT, 5, 5), 0u);           // equal → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULT, 1, 0xFFFFFFFFu), 1u); // 1 <u 0xFFFF… → true (differs from signed)
}

TEST(ExecutorTest, ICmpULE) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULE, 3, 5), 1u); // 3 <=u 5 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULE, 5, 5), 1u); // equal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_ULE, 5, 3), 0u); // 5 <=u 3 → false
}

TEST(ExecutorTest, ICmpSGT) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGT, 5, 3), 1u);           // 5 >s 3 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGT, 3, 5), 0u);           // 3 >s 5 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGT, 5, 5), 0u);           // equal → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGT, 1, 0xFFFFFFFFu), 1u); // 1 >s -1 → true (differs from unsigned)
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGT, 0xFFFFFFFFu, 1), 0u); // -1 >s 1 → false
}

TEST(ExecutorTest, ICmpSGE) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 5, 3), 1u);                     // 5 >=s 3 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 5, 5), 1u);                     // equal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 3, 5), 0u);                     // 3 >=s 5 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 1, 0xFFFFFFFFu), 1u);           // 1 >=s -1 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 0xFFFFFFFFu, 0xFFFFFFFFu), 1u); // -1 >=s -1 → true (equal)
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SGE, 0xFFFFFFFFu, 1), 0u);           // -1 >=s 1 → false
}

TEST(ExecutorTest, ICmpSLT) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLT, 3, 5), 1u);           // 3 <s 5 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLT, 5, 3), 0u);           // 5 <s 3 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLT, 5, 5), 0u);           // equal → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLT, 0xFFFFFFFFu, 1), 1u); // -1 <s 1 → true (differs from unsigned)
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLT, 1, 0xFFFFFFFFu), 0u); // 1 <s -1 → false
}

TEST(ExecutorTest, ICmpSLE) {
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 3, 5), 1u);                     // 3 <=s 5 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 5, 5), 1u);                     // equal → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 5, 3), 0u);                     // 5 <=s 3 → false
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 0xFFFFFFFFu, 1), 1u);           // -1 <=s 1 → true
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 0xFFFFFFFFu, 0xFFFFFFFFu), 1u); // -1 <=s -1 → true (equal)
    EXPECT_EQ(evalICmp(ICmpInst::ICMP_SLE, 1, 0xFFFFFFFFu), 0u);           // 1 <=s -1 → false
}

} // namespace
