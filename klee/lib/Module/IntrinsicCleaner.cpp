//===-- IntrinsicCleaner.cpp ----------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Passes.h"

#include <klee/Common.h>
#include <llvm/Support/raw_ostream.h>
#include "klee/Config/config.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace klee {

/* XXX: LLVM 2.7 have this built-in */
/// LowerBSWAP - Emit the code to lower bswap of V before the specified
/// instruction IP.
static Value *LowerBSWAP(LLVMContext &Context, Value *V, Instruction *IP) {
    assert(V->getType()->isIntegerTy() && "Can't bswap a non-integer type!");

    unsigned BitSize = V->getType()->getPrimitiveSizeInBits();

    IRBuilder<> Builder(IP);

    switch (BitSize) {
        default:
            llvm_unreachable("Unhandled type size of value to byteswap!");
        case 16: {
            Value *Tmp1 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 8), "bswap.2");
            Value *Tmp2 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 8), "bswap.1");
            V = Builder.CreateOr(Tmp1, Tmp2, "bswap.i16");
            break;
        }

        case 32: {
            Value *Tmp4 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 24), "bswap.4");
            Value *Tmp3 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 8), "bswap.3");
            Value *Tmp2 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 8), "bswap.2");
            Value *Tmp1 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 24), "bswap.1");
            Tmp3 = Builder.CreateAnd(Tmp3, ConstantInt::get(Type::getInt32Ty(Context), 0xFF0000), "bswap.and3");
            Tmp2 = Builder.CreateAnd(Tmp2, ConstantInt::get(Type::getInt32Ty(Context), 0xFF00), "bswap.and2");
            Tmp4 = Builder.CreateOr(Tmp4, Tmp3, "bswap.or1");
            Tmp2 = Builder.CreateOr(Tmp2, Tmp1, "bswap.or2");
            V = Builder.CreateOr(Tmp4, Tmp2, "bswap.i32");
            break;
        }

        case 64: {
            Value *Tmp8 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 56), "bswap.8");
            Value *Tmp7 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 40), "bswap.7");
            Value *Tmp6 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 24), "bswap.6");
            Value *Tmp5 = Builder.CreateShl(V, ConstantInt::get(V->getType(), 8), "bswap.5");
            Value *Tmp4 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 8), "bswap.4");
            Value *Tmp3 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 24), "bswap.3");
            Value *Tmp2 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 40), "bswap.2");
            Value *Tmp1 = Builder.CreateLShr(V, ConstantInt::get(V->getType(), 56), "bswap.1");
            Tmp7 =
                Builder.CreateAnd(Tmp7, ConstantInt::get(Type::getInt64Ty(Context), 0xFF000000000000ULL), "bswap.and7");
            Tmp6 =
                Builder.CreateAnd(Tmp6, ConstantInt::get(Type::getInt64Ty(Context), 0xFF0000000000ULL), "bswap.and6");
            Tmp5 = Builder.CreateAnd(Tmp5, ConstantInt::get(Type::getInt64Ty(Context), 0xFF00000000ULL), "bswap.and5");
            Tmp4 = Builder.CreateAnd(Tmp4, ConstantInt::get(Type::getInt64Ty(Context), 0xFF000000ULL), "bswap.and4");
            Tmp3 = Builder.CreateAnd(Tmp3, ConstantInt::get(Type::getInt64Ty(Context), 0xFF0000ULL), "bswap.and3");
            Tmp2 = Builder.CreateAnd(Tmp2, ConstantInt::get(Type::getInt64Ty(Context), 0xFF00ULL), "bswap.and2");
            Tmp8 = Builder.CreateOr(Tmp8, Tmp7, "bswap.or1");
            Tmp6 = Builder.CreateOr(Tmp6, Tmp5, "bswap.or2");
            Tmp4 = Builder.CreateOr(Tmp4, Tmp3, "bswap.or3");
            Tmp2 = Builder.CreateOr(Tmp2, Tmp1, "bswap.or4");
            Tmp8 = Builder.CreateOr(Tmp8, Tmp6, "bswap.or5");
            Tmp4 = Builder.CreateOr(Tmp4, Tmp2, "bswap.or6");
            V = Builder.CreateOr(Tmp8, Tmp4, "bswap.i64");
            break;
        }
    }
    return V;
}

char IntrinsicCleanerPass::ID;

void IntrinsicCleanerPass::replaceIntrinsicAdd(Module &M, CallInst *CI) {
    Value *arg0 = CI->getArgOperand(0);
    Value *arg1 = CI->getArgOperand(1);

    IntegerType *itype = static_cast<IntegerType *>(arg0->getType());
    assert(itype);

    Function *f = nullptr;
    switch (itype->getBitWidth()) {
        case 16:
            f = M.getFunction("uadds");
            break;
        case 32:
            f = M.getFunction("uadd");
            break;
        case 64:
            f = M.getFunction("uaddl");
            break;
        default:
            pabort("Invalid intrinsic type");
    }

    check(f, "Could not find intrinsic replacements for add with overflow");

    StructType *aggregate = static_cast<StructType *>(CI->getCalledFunction()->getReturnType());

    std::vector<Value *> args;

    auto as = M.getDataLayout().getAllocaAddrSpace();
    Value *alloca = new AllocaInst(itype, as, NULL, "", CI);
    args.push_back(alloca);
    args.push_back(arg0);
    args.push_back(arg1);
    Value *overflow = CallInst::Create(f, args, "", CI);

    // Store the values in the aggregated type
    Value *aggrValPtr = new AllocaInst(aggregate, as, NULL, "", CI);
    Value *aggrVal = new LoadInst(aggrValPtr->getType()->getPointerElementType(), aggrValPtr, "", CI);
    Value *addResult = new LoadInst(alloca->getType()->getPointerElementType(), alloca, "", CI);
    InsertValueInst *insRes = InsertValueInst::Create(aggrVal, addResult, 0, "", CI);
    InsertValueInst *insOverflow = InsertValueInst::Create(insRes, overflow, 1, "", CI);
    CI->replaceAllUsesWith(insOverflow);
    CI->eraseFromParent();
}

/**
 * Inject a function of the following form:
 * define i1 @uadds(i16*, i16, i16) {
 *   %4 = add i16 %1, %2
 *   store i16 %4, i16* %0
 *   %5 = icmp ugt i16 %1, %2
 *   %6 = select i1 %5, i16 %1, i16 %2
 *   %7 = icmp ult i16 %4, %6
 *   ret i1 %7
 *  }
 *
 * These functions replace the add with overflow intrinsics
 * used by LLVM. These intrinsics have a {iXX, i1} return type,
 * which causes problems if the size of the type is less than 64 bits.
 * clang basically packs such a type into a 64-bits integer, which causes
 * a silent type mismatch and data corruptions when KLEE tries
 * to interpret such a value with its extract instructions.
 * We therefore manually implement the functions here, to avoid using clang.
 */

void IntrinsicCleanerPass::injectIntrinsicAddImplementation(Module &M, const std::string &name, unsigned bits) {
    Function *f = M.getFunction(name);
    if (f) {
        assert(!f->isDeclaration());
        return;
    }

    LLVMContext &ctx = M.getContext();
    std::vector<Type *> argTypes;
    argTypes.push_back(Type::getIntNPtrTy(ctx, bits)); // Result
    argTypes.push_back(Type::getIntNTy(ctx, bits));    // a
    argTypes.push_back(Type::getIntNTy(ctx, bits));    // b

    FunctionType *type = FunctionType::get(Type::getInt1Ty(ctx), ArrayRef<Type *>(argTypes), false);
    f = dyn_cast<Function>(M.getOrInsertFunction(name, type).getCallee());
    assert(f);

    BasicBlock *bb = BasicBlock::Create(ctx, "", f);
    IRBuilder<> builder(bb);

    std::vector<Value *> args;
    Function::arg_iterator it = f->arg_begin();
    args.push_back(&*it++);
    args.push_back(&*it++);
    args.push_back(&*it++);

    Value *res = builder.CreateAdd(args[1], args[2]);
    builder.CreateStore(res, args[0]);
    Value *cmp = builder.CreateICmpUGT(args[1], args[2]);
    Value *cond = builder.CreateSelect(cmp, args[1], args[2]);
    Value *cmp1 = builder.CreateICmpULT(res, cond);
    builder.CreateRet(cmp1);
}

bool IntrinsicCleanerPass::runOnModule(Module &M) {
    bool dirty = true;

    injectIntrinsicAddImplementation(M, "uadds", 16);
    injectIntrinsicAddImplementation(M, "uadd", 32);
    injectIntrinsicAddImplementation(M, "uaddl", 64);

    for (Module::iterator f = M.begin(), fe = M.end(); f != fe; ++f)
        for (Function::iterator b = f->begin(), be = f->end(); b != be;)
            dirty |= runOnBasicBlock(*(b++), M);
    return dirty;
}

bool IntrinsicCleanerPass::runOnBasicBlock(BasicBlock &b, Module &M) {
    bool dirty = false;
    LLVMContext &ctx = M.getContext();

    unsigned WordSize = DataLayout.getPointerSizeInBits() / 8;
    for (BasicBlock::iterator i = b.begin(), ie = b.end(); i != ie;) {
        IntrinsicInst *ii = dyn_cast<IntrinsicInst>(&*i);
        // increment now since deletion of instructions makes iterator invalid.
        ++i;
        if (ii) {
            if (isa<DbgInfoIntrinsic>(ii))
                continue;

            switch (ii->getIntrinsicID()) {
                case Intrinsic::vastart:
                case Intrinsic::vaend:
                case Intrinsic::fabs:
                case Intrinsic::fshr:
                case Intrinsic::fshl:

                case Intrinsic::abs:
                case Intrinsic::smax:
                case Intrinsic::smin:
                case Intrinsic::umax:
                case Intrinsic::umin:
                    break;

                    // Lower vacopy so that object resolution etc is handled by
                    // normal instructions.
                    //
                    // FIXME: This is much more target dependent than just the word size,
                    // however this works for x86-32 and x86-64.
                case Intrinsic::vacopy: { // (dst, src) -> *((i8**) dst) = *((i8**) src)
                    llvm::IRBuilder<> Builder(ii);
                    Value *dst = ii->getArgOperand(0);
                    Value *src = ii->getArgOperand(1);

                    if (WordSize == 4) {
                        Type *i8pp = PointerType::getUnqual(PointerType::getUnqual(Type::getInt8Ty(ctx)));
                        auto castedDst = Builder.CreatePointerCast(dst, i8pp, "vacopy.cast.dst");
                        auto castedSrc = Builder.CreatePointerCast(src, i8pp, "vacopy.cast.src");
                        auto load =
                            Builder.CreateLoad(castedSrc->getType()->getPointerElementType(), castedSrc, "vacopy.read");
                        Builder.CreateStore(load, castedDst, false /* isVolatile */);
                    } else {
                        assert(WordSize == 8 && "Invalid word size!");
                        Type *i64p = PointerType::getUnqual(Type::getInt64Ty(ctx));
                        auto pDst = Builder.CreatePointerCast(dst, i64p, "vacopy.cast.dst");
                        auto pSrc = Builder.CreatePointerCast(src, i64p, "vacopy.cast.src");

                        auto pSrcType = pSrc->getType()->getPointerElementType();
                        auto pDstType = pDst->getType()->getPointerElementType();

                        auto val = Builder.CreateLoad(pSrcType, pSrc);
                        Builder.CreateStore(val, pDst, ii);

                        auto off = ConstantInt::get(Type::getInt64Ty(ctx), 1);
                        pDst = Builder.CreateGEP(pDstType, pDst, off);
                        pSrc = Builder.CreateGEP(pSrcType, pSrc, off);
                        val = Builder.CreateLoad(pSrcType, pSrc);
                        Builder.CreateStore(val, pDst);
                        pDst = Builder.CreateGEP(pDstType, pDst, off);
                        pSrc = Builder.CreateGEP(pSrcType, pSrc, off);
                        val = Builder.CreateLoad(pSrcType, pSrc);
                        Builder.CreateStore(val, pDst);
                    }
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                }

                case Intrinsic::sadd_with_overflow:
                case Intrinsic::ssub_with_overflow:
                case Intrinsic::smul_with_overflow:
                case Intrinsic::uadd_with_overflow:
                case Intrinsic::usub_with_overflow:
                case Intrinsic::umul_with_overflow: {
                    IRBuilder<> builder(ii->getParent(), ii->getIterator());

                    Value *op1 = ii->getArgOperand(0);
                    Value *op2 = ii->getArgOperand(1);

                    Value *result = 0;
                    Value *result_ext = 0;
                    Value *overflow = 0;

                    unsigned int bw = op1->getType()->getPrimitiveSizeInBits();
                    unsigned int bw2 = op1->getType()->getPrimitiveSizeInBits() * 2;

                    if ((ii->getIntrinsicID() == Intrinsic::uadd_with_overflow) ||
                        (ii->getIntrinsicID() == Intrinsic::usub_with_overflow) ||
                        (ii->getIntrinsicID() == Intrinsic::umul_with_overflow)) {

                        Value *op1ext = builder.CreateZExt(op1, IntegerType::get(M.getContext(), bw2));
                        Value *op2ext = builder.CreateZExt(op2, IntegerType::get(M.getContext(), bw2));
                        Value *int_max_s = ConstantInt::get(op1->getType(), APInt::getMaxValue(bw));
                        Value *int_max = builder.CreateZExt(int_max_s, IntegerType::get(M.getContext(), bw2));

                        if (ii->getIntrinsicID() == Intrinsic::uadd_with_overflow) {
                            result_ext = builder.CreateAdd(op1ext, op2ext);
                        } else if (ii->getIntrinsicID() == Intrinsic::usub_with_overflow) {
                            result_ext = builder.CreateSub(op1ext, op2ext);
                        } else if (ii->getIntrinsicID() == Intrinsic::umul_with_overflow) {
                            result_ext = builder.CreateMul(op1ext, op2ext);
                        }
                        overflow = builder.CreateICmpUGT(result_ext, int_max);

                    } else if ((ii->getIntrinsicID() == Intrinsic::sadd_with_overflow) ||
                               (ii->getIntrinsicID() == Intrinsic::ssub_with_overflow) ||
                               (ii->getIntrinsicID() == Intrinsic::smul_with_overflow)) {

                        Value *op1ext = builder.CreateSExt(op1, IntegerType::get(M.getContext(), bw2));
                        Value *op2ext = builder.CreateSExt(op2, IntegerType::get(M.getContext(), bw2));
                        Value *int_max_s = ConstantInt::get(op1->getType(), APInt::getSignedMaxValue(bw));
                        Value *int_min_s = ConstantInt::get(op1->getType(), APInt::getSignedMinValue(bw));
                        Value *int_max = builder.CreateSExt(int_max_s, IntegerType::get(M.getContext(), bw2));
                        Value *int_min = builder.CreateSExt(int_min_s, IntegerType::get(M.getContext(), bw2));

                        if (ii->getIntrinsicID() == Intrinsic::sadd_with_overflow) {
                            result_ext = builder.CreateAdd(op1ext, op2ext);
                        } else if (ii->getIntrinsicID() == Intrinsic::ssub_with_overflow) {
                            result_ext = builder.CreateSub(op1ext, op2ext);
                        } else if (ii->getIntrinsicID() == Intrinsic::smul_with_overflow) {
                            result_ext = builder.CreateMul(op1ext, op2ext);
                        }
                        overflow = builder.CreateOr(builder.CreateICmpSGT(result_ext, int_max),
                                                    builder.CreateICmpSLT(result_ext, int_min));
                    }

                    // This trunc cound be replaced by a more general trunc replacement
                    // that allows to detect also undefined behavior in assignments or
                    // overflow in operation with integers whose dimension is smaller than
                    // int's dimension, e.g.
                    //     uint8_t = uint8_t + uint8_t;
                    // if one desires the wrapping should write
                    //     uint8_t = (uint8_t + uint8_t) & 0xFF;
                    // before this, must check if it has side effects on other operations
                    result = builder.CreateTrunc(result_ext, op1->getType());
                    Value *resultStruct = builder.CreateInsertValue(UndefValue::get(ii->getType()), result, 0);
                    resultStruct = builder.CreateInsertValue(resultStruct, overflow, 1);

                    ii->replaceAllUsesWith(resultStruct);
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                }

                case Intrinsic::sadd_sat:
                case Intrinsic::ssub_sat:
                case Intrinsic::uadd_sat:
                case Intrinsic::usub_sat: {
                    IRBuilder<> builder(ii);

                    Value *op1 = ii->getArgOperand(0);
                    Value *op2 = ii->getArgOperand(1);

                    unsigned int bw = op1->getType()->getPrimitiveSizeInBits();
                    assert(bw == op2->getType()->getPrimitiveSizeInBits());

                    Value *overflow = nullptr;
                    Value *result = nullptr;
                    Value *saturated = nullptr;
                    switch (ii->getIntrinsicID()) {
                        case Intrinsic::usub_sat:
                            result = builder.CreateSub(op1, op2);
                            overflow = builder.CreateICmpULT(op1, op2); // a < b  =>  a - b < 0
                            saturated = ConstantInt::get(ctx, APInt(bw, 0));
                            break;
                        case Intrinsic::uadd_sat:
                            result = builder.CreateAdd(op1, op2);
                            overflow = builder.CreateICmpULT(result, op1); // a + b < a
                            saturated = ConstantInt::get(ctx, APInt::getMaxValue(bw));
                            break;
                        case Intrinsic::ssub_sat:
                        case Intrinsic::sadd_sat: {
                            if (ii->getIntrinsicID() == Intrinsic::ssub_sat) {
                                result = builder.CreateSub(op1, op2);
                            } else {
                                result = builder.CreateAdd(op1, op2);
                            }
                            ConstantInt *zero = ConstantInt::get(ctx, APInt(bw, 0));
                            ConstantInt *smin = ConstantInt::get(ctx, APInt::getSignedMinValue(bw));
                            ConstantInt *smax = ConstantInt::get(ctx, APInt::getSignedMaxValue(bw));

                            Value *sign1 = builder.CreateICmpSLT(op1, zero);
                            Value *sign2 = builder.CreateICmpSLT(op2, zero);
                            Value *signR = builder.CreateICmpSLT(result, zero);

                            if (ii->getIntrinsicID() == Intrinsic::ssub_sat) {
                                saturated = builder.CreateSelect(sign2, smax, smin);
                            } else {
                                saturated = builder.CreateSelect(sign2, smin, smax);
                            }

                            // The sign of the result differs from the sign of the first operand
                            overflow = builder.CreateXor(sign1, signR);
                            if (ii->getIntrinsicID() == Intrinsic::ssub_sat) {
                                // AND the signs of the operands differ
                                overflow = builder.CreateAnd(overflow, builder.CreateXor(sign1, sign2));
                            } else {
                                // AND the signs of the operands are the same
                                overflow =
                                    builder.CreateAnd(overflow, builder.CreateNot(builder.CreateXor(sign1, sign2)));
                            }
                            break;
                        }
                        default:;
                    }

                    result = builder.CreateSelect(overflow, saturated, result);
                    ii->replaceAllUsesWith(result);
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                }

                case Intrinsic::trap: {
                    // Intrinsic instruction "llvm.trap" found. Directly lower it to
                    // a call of the abort() function.
                    auto C = M.getOrInsertFunction("abort", Type::getVoidTy(ctx));
                    if (auto *F = dyn_cast<Function>(C.getCallee())) {
                        F->setDoesNotReturn();
                        F->setDoesNotThrow();
                    }

                    llvm::IRBuilder<> Builder(ii);
                    Builder.CreateCall(C);
                    Builder.CreateUnreachable();

                    i = ii->eraseFromParent();

                    // check if the instruction after the one we just replaced is not the
                    // end of the basic block and if it is not (i.e. it is a valid
                    // instruction), delete it and all remaining because the cleaner just
                    // introduced a terminating instruction (unreachable) otherwise llvm will
                    // assert in Verifier::visitTerminatorInstr
                    while (i != ie) { // i was already incremented above.
                        i = i->eraseFromParent();
                    }

                    dirty = true;
                    break;
                }
                case Intrinsic::objectsize: {
                    // Lower the call to a concrete value
                    auto replacement = llvm::lowerObjectSizeCall(ii, DataLayout, nullptr,
                                                                 /*MustSucceed=*/true);
                    ii->replaceAllUsesWith(replacement);
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                }

                case Intrinsic::is_constant: {
                    if (auto *constant = llvm::ConstantFoldInstruction(ii, ii->getModule()->getDataLayout()))
                        ii->replaceAllUsesWith(constant);
                    else
                        ii->replaceAllUsesWith(ConstantInt::getFalse(ii->getType()));
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                }

                // The following intrinsics are currently handled by LowerIntrinsicCall
                // (Invoking LowerIntrinsicCall with any intrinsics not on this
                // list throws an exception.)
                case Intrinsic::addressofreturnaddress:
                case Intrinsic::annotation:
                case Intrinsic::assume:
                case Intrinsic::bswap:
                case Intrinsic::ceil:
                case Intrinsic::copysign:
                case Intrinsic::cos:
                case Intrinsic::ctlz:
                case Intrinsic::ctpop:
                case Intrinsic::cttz:
                case Intrinsic::dbg_declare:
                case Intrinsic::dbg_label:
                case Intrinsic::eh_typeid_for:
                case Intrinsic::exp2:
                case Intrinsic::exp:
                case Intrinsic::expect:
                case Intrinsic::floor:
                case Intrinsic::flt_rounds:
                case Intrinsic::frameaddress:
                case Intrinsic::get_dynamic_area_offset:
                case Intrinsic::invariant_end:
                case Intrinsic::invariant_start:
                case Intrinsic::lifetime_end:
                case Intrinsic::lifetime_start:
                case Intrinsic::log10:
                case Intrinsic::log2:
                case Intrinsic::log:
                case Intrinsic::memcpy:
                case Intrinsic::memmove:
                case Intrinsic::memset:
                case Intrinsic::not_intrinsic:
                case Intrinsic::pcmarker:
                case Intrinsic::pow:
                case Intrinsic::prefetch:
                case Intrinsic::ptr_annotation:
                case Intrinsic::readcyclecounter:
                case Intrinsic::returnaddress:
                case Intrinsic::round:
                case Intrinsic::roundeven:
                case Intrinsic::sin:
                case Intrinsic::sqrt:
                case Intrinsic::stackrestore:
                case Intrinsic::stacksave:
                case Intrinsic::trunc:
                case Intrinsic::var_annotation:
                    IL->LowerIntrinsicCall(ii);
                    dirty = true;
                    break;

                    // Warn about any unrecognized intrinsics.
                default: {
                    const Function *Callee = ii->getCalledFunction();
                    llvm::StringRef name = Callee->getName();
                    klee_warning_once((void *) Callee, "unsupported intrinsic %.*s", (int) name.size(), name.data());
                    break;
                }
            }
        }
    }

    return dirty;
}

char IntrinsicFunctionCleanerPass::ID;

bool IntrinsicFunctionCleanerPass::runOnFunction(llvm::Function &F) {
    bool dirty = false;

    for (Function::iterator b = F.begin(), be = F.end(); b != be; ++b)
        dirty |= runOnBasicBlock(*b);
    return dirty;
}

bool IntrinsicFunctionCleanerPass::runOnBasicBlock(llvm::BasicBlock &b) {
    bool dirty = false;
    LLVMContext &context = b.getContext();

    for (BasicBlock::iterator i = b.begin(), ie = b.end(); i != ie;) {
        IntrinsicInst *ii = dyn_cast<IntrinsicInst>(&*i);
        // increment now since LowerIntrinsic deletion makes iterator invalid.
        ++i;
        if (ii) {
            switch (ii->getIntrinsicID()) {
                case Intrinsic::bswap:
                    ii->replaceAllUsesWith(LowerBSWAP(context, ii->getArgOperand(0), ii));
                    ii->eraseFromParent();
                    break;
                default:
                    break;
            }
        }
    }

    return dirty;
}
} // namespace klee
