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
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
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

/// ReplaceCallWith - This function is used when we want to lower an intrinsic
/// call to a call of an external function.  This handles hard cases such as
/// when there was already a prototype for the external function, and if that
/// prototype doesn't match the arguments we expect to pass in.
template <class ArgIt>
static CallInst *ReplaceCallWith(const char *NewFn, CallInst *CI, ArgIt ArgBegin, ArgIt ArgEnd, Type *RetTy) {
    // If we haven't already looked up this function, check to see if the
    // program already contains a function with this name.
    Module *M = CI->getParent()->getParent()->getParent();
    // Get or insert the definition now.
    std::vector<Type *> ParamTys;
    for (ArgIt I = ArgBegin; I != ArgEnd; ++I)
        ParamTys.push_back((*I)->getType());

    llvm::ArrayRef<Type *> ParamTysA(&ParamTys[0], ParamTys.size());

    auto FCache = M->getOrInsertFunction(NewFn, FunctionType::get(RetTy, ParamTysA, false));

    IRBuilder<> Builder(CI);
    SmallVector<Value *, 8> Args(ArgBegin, ArgEnd);

    CallInst *NewCI = Builder.CreateCall(FCache, llvm::ArrayRef<Value *>(Args));
    NewCI->setName(CI->getName());
    if (!CI->use_empty())
        CI->replaceAllUsesWith(NewCI);
    CI->eraseFromParent();
    return NewCI;
}

static void ReplaceFPIntrinsicWithCall(CallInst *CI, const char *Fname, const char *Dname, const char *LDname) {
    CallSite CS(CI);

    switch (CI->getArgOperand(0)->getType()->getTypeID()) {
        default:
            pabort("Invalid type in intrinsic");
        case Type::FloatTyID:
            ReplaceCallWith(Fname, CI, CS.arg_begin(), CS.arg_end(), Type::getFloatTy(CI->getContext()));
            break;

        case Type::DoubleTyID:
            ReplaceCallWith(Dname, CI, CS.arg_begin(), CS.arg_end(), Type::getDoubleTy(CI->getContext()));
            break;

        case Type::X86_FP80TyID:
        case Type::FP128TyID:
        case Type::PPC_FP128TyID:
            ReplaceCallWith(LDname, CI, CS.arg_begin(), CS.arg_end(), CI->getArgOperand(0)->getType());
            break;
    }
}

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
    Value *aggrVal = new LoadInst(aggrValPtr, "", CI);
    Value *addResult = new LoadInst(alloca, "", CI);
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
            dirty |= runOnBasicBlock(*(b++));
    return dirty;
}

bool IntrinsicCleanerPass::runOnFunction(Function &F) {
    bool dirty = false;
    for (Function::iterator b = F.begin(), be = F.end(); b != be;)
        dirty |= runOnBasicBlock(*(b++));
    return dirty;
}

bool IntrinsicCleanerPass::runOnBasicBlock(BasicBlock &b) {
    bool dirty = false;
    LLVMContext &context = b.getContext();

    unsigned WordSize = DataLayout.getPointerSizeInBits() / 8;
    for (BasicBlock::iterator i = b.begin(), ie = b.end(); i != ie;) {
        IntrinsicInst *ii = dyn_cast<IntrinsicInst>(&*i);
        // increment now since LowerIntrinsic deletion makes iterator invalid.
        ++i;
        if (ii) {
            CallSite CS(ii);

            switch (ii->getIntrinsicID()) {
                case Intrinsic::vastart:
                case Intrinsic::vaend:
                    break;

                // Lower vacopy so that object resolution etc is handled by
                // normal instructions.
                //
                // FIXME: This is much more target dependent than just the word size,
                // however this works for x86-32 and x86-64.
                case Intrinsic::vacopy: { // (dst, src) -> *((i8**) dst) = *((i8**) src)
                    Value *dst = ii->getArgOperand(0);
                    Value *src = ii->getArgOperand(1);

                    if (WordSize == 4) {
                        Type *i8pp = PointerType::getUnqual(PointerType::getUnqual(Type::getInt8Ty(context)));
                        Value *castedDst = CastInst::CreatePointerCast(dst, i8pp, "vacopy.cast.dst", ii);
                        Value *castedSrc = CastInst::CreatePointerCast(src, i8pp, "vacopy.cast.src", ii);
                        Value *load = new LoadInst(castedSrc, "vacopy.read", ii);
                        new StoreInst(load, castedDst, false, ii);
                    } else {
                        assert(WordSize == 8 && "Invalid word size!");
                        Type *i64p = PointerType::getUnqual(Type::getInt64Ty(context));
                        Value *pDst = CastInst::CreatePointerCast(dst, i64p, "vacopy.cast.dst", ii);
                        Value *pSrc = CastInst::CreatePointerCast(src, i64p, "vacopy.cast.src", ii);
                        Value *val = new LoadInst(pSrc, std::string(), ii);
                        new StoreInst(val, pDst, ii);
                        Value *off = ConstantInt::get(Type::getInt64Ty(context), 1);
                        pDst = GetElementPtrInst::Create(nullptr, pDst, off, std::string(), ii);
                        pSrc = GetElementPtrInst::Create(nullptr, pSrc, off, std::string(), ii);
                        val = new LoadInst(pSrc, std::string(), ii);
                        new StoreInst(val, pDst, ii);
                        pDst = GetElementPtrInst::Create(nullptr, pDst, off, std::string(), ii);
                        pSrc = GetElementPtrInst::Create(nullptr, pSrc, off, std::string(), ii);
                        val = new LoadInst(pSrc, std::string(), ii);
                        new StoreInst(val, pDst, ii);
                    }
                    ii->removeFromParent();
                    delete ii;
                    break;
                }

                case Intrinsic::dbg_value:
                case Intrinsic::dbg_declare:
                    // Remove these regardless of lower intrinsics flag. This can
                    // be removed once IntrinsicLowering is fixed to not have bad
                    // caches.
                    ii->eraseFromParent();
                    dirty = true;
                    break;
                    // case Intrinsic::memory_barrier:
                    // case Intrinsic::atomic_swap:
                    // case Intrinsic::atomic_cmp_swap:
                    // case Intrinsic::atomic_load_add:
                    // case Intrinsic::atomic_load_sub:
                    break;

                case Intrinsic::powi:
                    ReplaceFPIntrinsicWithCall(ii, "powif", "powi", "powil");
                    dirty = true;
                    break;

                case Intrinsic::uadd_with_overflow:
                    replaceIntrinsicAdd(*b.getParent()->getParent(), ii);
                    dirty = true;
                    break;

                case Intrinsic::rint:
                    ReplaceFPIntrinsicWithCall(ii, "rintf", "rint", "rintl");
                    dirty = true;
                    break;

                case Intrinsic::fabs:
                    ReplaceFPIntrinsicWithCall(ii, "fabsf", "fabs", "fabsl");
                    dirty = true;
                    break;

                case Intrinsic::trap:
                    // Link with abort
                    ReplaceCallWith("abort", ii, CS.arg_end(), CS.arg_end(), Type::getVoidTy(context));
                    dirty = true;
                    break;

                case Intrinsic::memset:
                case Intrinsic::memcpy:
                case Intrinsic::memmove: {
                    LLVMContext &Ctx = ii->getContext();

                    Value *dst = ii->getArgOperand(0);
                    Value *src = ii->getArgOperand(1);
                    Value *len = ii->getArgOperand(2);

                    BasicBlock *BB = ii->getParent();
                    Function *F = BB->getParent();

                    BasicBlock *exitBB = BB->splitBasicBlock(ii);
                    BasicBlock *headerBB = BasicBlock::Create(Ctx, Twine(), F, exitBB);
                    BasicBlock *bodyBB = BasicBlock::Create(Ctx, Twine(), F, exitBB);

                    // Enter the loop header
                    BB->getTerminator()->eraseFromParent();
                    BranchInst::Create(headerBB, BB);

                    // Create loop index
                    PHINode *idx = PHINode::Create(len->getType(), 0, Twine(), headerBB);
                    idx->addIncoming(ConstantInt::get(len->getType(), 0), BB);

                    // Check loop condition, then move to the loop body or exit the loop
                    Value *loopCond =
                        ICmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_ULT, idx, len, Twine(), headerBB);
                    BranchInst::Create(bodyBB, exitBB, loopCond, headerBB);

                    // Get value to store
                    Value *val;
                    if (ii->getIntrinsicID() == Intrinsic::memset) {
                        val = src;
                    } else {
                        Value *srcPtr = GetElementPtrInst::Create(nullptr, src, idx, Twine(), bodyBB);
                        val = new LoadInst(srcPtr, Twine(), bodyBB);
                    }

                    // Store the value
                    Value *dstPtr = GetElementPtrInst::Create(nullptr, dst, idx, Twine(), bodyBB);
                    new StoreInst(val, dstPtr, bodyBB);

                    // Update index and branch back
                    Value *newIdx = BinaryOperator::Create(Instruction::Add, idx, ConstantInt::get(len->getType(), 1),
                                                           Twine(), bodyBB);
                    BranchInst::Create(headerBB, bodyBB);
                    idx->addIncoming(newIdx, bodyBB);

                    ii->eraseFromParent();

                    // Update iterators to continue in the next BB
                    i = exitBB->begin();
                    ie = exitBB->end();
                    break;
                }

                default:
                    if (LowerIntrinsics)
                        IL->LowerIntrinsicCall(ii);
                    dirty = true;
                    break;
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
