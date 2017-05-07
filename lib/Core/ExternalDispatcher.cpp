//===-- ExternalDispatcher.cpp --------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ExternalDispatcher.h"
#include "klee/Config/config.h"

// Ugh.
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#if (LLVM_VERSION_MAJOR == 2 && LLVM_VERSION_MINOR < 7)
#include "llvm/ModuleProvider.h"
#endif
#if !(LLVM_VERSION_MAJOR == 2 && LLVM_VERSION_MINOR < 7)
#include "llvm/IR/LLVMContext.h"
#endif
#include <iostream>
#include <setjmp.h>
#include <signal.h>
#include <sstream>
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace klee;

/***/

static jmp_buf escapeCallJmpBuf;

extern "C" {

#ifdef _WIN32
static void sigsegv_handler(int signal) {
}
#else
static void sigsegv_handler(int signal, siginfo_t *info, void *context) {
    longjmp(escapeCallJmpBuf, 1);
}
#endif
}

void *ExternalDispatcher::resolveSymbol(const std::string &name) {
    const char *str = name.c_str();

    // We use this to validate that function names can be resolved so we
    // need to match how the JIT does it. Unfortunately we can't
    // directly access the JIT resolution function
    // JIT::getPointerToNamedFunction so we emulate the important points.

    if (str[0] == 1) // asm specifier, skipped
        ++str;

    void *addr = sys::DynamicLibrary::SearchForAddressOfSymbol(str);
    if (addr)
        return addr;

    // If it has an asm specifier and starts with an underscore we retry
    // without the underscore. I (DWD) don't know why.
    if (name[0] == 1 && str[0] == '_') {
        ++str;
        addr = sys::DynamicLibrary::SearchForAddressOfSymbol(str);
    }

    return addr;
}

ExternalDispatcher::ExternalDispatcher(LLVMContext &ctx) : context(ctx) {
    // If we have a native target, initialize it to ensure it is linked in and
    // usable by the JIT.
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeNativeTargetAsmParser();
    llvm::InitializeNativeTargetDisassembler();

#ifdef WINDOWS
    preboundFunctions["getpid"] = (void *) (uintptr_t) getpid;
    preboundFunctions["putchar"] = (void *) (uintptr_t) putchar;
    preboundFunctions["printf"] = (void *) (uintptr_t) printf;
    preboundFunctions["fprintf"] = (void *) (uintptr_t) fprintf;
    preboundFunctions["sprintf"] = (void *) (uintptr_t) sprintf;
#endif
}

ExternalDispatcher::~ExternalDispatcher() {
    for (auto it = executionEngines.begin(), end = executionEngines.end(); it != end; ++it) {
        delete it->second;
    }
}

bool ExternalDispatcher::executeCall(Function *f, Instruction *i, uint64_t *args) {
    dispatchers_ty::iterator it = dispatchers.find(i);
    Function *dispatcher;

    if (it == dispatchers.end()) {
#ifdef WINDOWS
    std::map<std::string, void*>::iterator it2 =
      preboundFunctions.find(f->getName()));

    if (it2 != preboundFunctions.end()) {
        // only bind once
        if (it2->second) {
            executionEngine->addGlobalMapping(f, it2->second);
            it2->second = 0;
        }
    }
#endif

    dispatcher = createDispatcher(f, i);

    dispatchers.insert(std::make_pair(i, dispatcher));
    } else {
        dispatcher = it->second;
    }

    return runProtectedCall(dispatcher, args);
}

// FIXME: This is not reentrant.
uint64_t *ExternalDispatcher::gTheArgsP;

bool ExternalDispatcher::runProtectedCall(Function *f, uint64_t *args) {
#ifndef _WIN32
    struct sigaction segvAction, segvActionOld;
#endif
    bool res;

    if (!f)
        return false;

    std::vector<GenericValue> gvArgs;
    gTheArgsP = args;

#ifdef _WIN32
    signal(SIGSEGV, ::sigsegv_handler);
#else
    segvAction.sa_handler = 0;
    memset(&segvAction.sa_mask, 0, sizeof(segvAction.sa_mask));
    segvAction.sa_flags = SA_SIGINFO;
    segvAction.sa_sigaction = ::sigsegv_handler;
    sigaction(SIGSEGV, &segvAction, &segvActionOld);
#endif

    if (setjmp(escapeCallJmpBuf)) {
        res = false;
    } else {
        llvm::ExecutionEngine *EE = getExecutionEngine(f);
        EE->runFunction(f, gvArgs);
        res = true;
    }

#ifdef _WIN32
#warning Implement more robust signal handling on windows
    signal(SIGSEGV, SIG_IGN);
#else
    sigaction(SIGSEGV, &segvActionOld, 0);
#endif
    return res;
}

// For performance purposes we construct the stub in such a way that the
// arguments pointer is passed through the static global variable gTheArgsP in
// this file. This is done so that the stub function prototype trivially matches
// the special cases that the JIT knows how to directly call. If this is not
// done, then the jit will end up generating a nullary stub just to call our
// stub, for every single function call.
Function *ExternalDispatcher::createDispatcher(Function *target, Instruction *inst) {
    // Name the external function. LLVM's MCJIT requires named functions, so
    // generate a unique name.
    std::ostringstream oss;
    oss << "__klee_ext__" << target->getName().str();

    CallSite cs;
    if (inst->getOpcode() == Instruction::Call) {
        cs = CallSite(cast<CallInst>(inst));
    } else {
        cs = CallSite(cast<InvokeInst>(inst));
    }

    Value **args = new Value *[cs.arg_size()];

    std::vector<Type *> nullary;
    llvm::Module *M = getModuleForNewFunction(target);

    Function *dispatcher =
        Function::Create(FunctionType::get(Type::getVoidTy(context), ArrayRef<Type *>(nullary), false),
                         GlobalVariable::ExternalLinkage, oss.str(), M);

    BasicBlock *dBB = BasicBlock::Create(context, "entry", dispatcher);

    // Get a Value* for &gTheArgsP, as an i64**.
    Instruction *argI64sp =
        new IntToPtrInst(ConstantInt::get(Type::getInt64Ty(context), (uintptr_t)(void *) &gTheArgsP),
                         PointerType::getUnqual(PointerType::getUnqual(Type::getInt64Ty(context))), "argsp", dBB);
    Instruction *argI64s = new LoadInst(argI64sp, "args", dBB);

    // Get the target function type.
    FunctionType *FTy = cast<FunctionType>(cast<PointerType>(target->getType())->getElementType());

    // Each argument will be passed by writing it into gTheArgsP[i].
    unsigned i = 0;
    for (CallSite::arg_iterator ai = cs.arg_begin(), ae = cs.arg_end(); ai != ae; ++ai, ++i) {
        // Determine the type the argument will be passed as. This accomodates for
        // the corresponding code in Executor.cpp for handling calls to bitcasted
        // functions.
        Type *argTy = (i < FTy->getNumParams() ? FTy->getParamType(i) : (*ai)->getType());
        Instruction *argI64p =
            GetElementPtrInst::Create(nullptr, argI64s, ConstantInt::get(Type::getInt32Ty(context), i + 1), "", dBB);

        Instruction *argp = new BitCastInst(argI64p, PointerType::getUnqual(argTy), "", dBB);
        args[i] = new LoadInst(argp, "", dBB);
    }

    /////////////////////
    // S2E modification
    // The original KLEE code issued a call instruction to the external function
    // represented by a plain llvm::Function. The LLVM JIT would create a stub
    // for such a call. The stub and the JITed function (the one returned by this method)
    // must be close enough in memory because the JIT generates a machine call instruction
    // that uses a relative 32-bits displacement. Unfortunately, the default JIT memory
    // manager allocates blocks of code too far apart for a 32-bit value.
    // To solve this, we create an absolute call by casting the native pointer to
    // the helper to the type of that helper.

    uintptr_t targetFunctionAddress =
        (uintptr_t) llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(target->getName());

    assert(targetFunctionAddress && "External function not registered");

    Instruction *toPtr = new IntToPtrInst(
        ConstantInt::get(Type::getInt64Ty(context), APInt(sizeof(targetFunctionAddress) * 8, targetFunctionAddress)),
        PointerType::get(Type::getInt64Ty(context), 0), "", dBB);

    Instruction *dispatchTarget = new BitCastInst(toPtr, cs.getCalledValue()->getType(), "", dBB);

    /////////////////////
    // S2E code
    /////////////////////

    Instruction *result = CallInst::Create(dispatchTarget, ArrayRef<Value *>(args, cs.arg_size()), "", dBB);
    if (result->getType() != Type::getVoidTy(context)) {
        Instruction *resp = new BitCastInst(argI64s, PointerType::getUnqual(result->getType()), "", dBB);
        new StoreInst(result, resp, dBB);
    }

    ReturnInst::Create(context, dBB);

    delete[] args;

    return dispatcher;
}

llvm::ExecutionEngine *ExternalDispatcher::getExecutionEngine(llvm::Function *func) {
    auto eeIt = executionEngines.find(func->getParent());
    if (eeIt != executionEngines.end()) {
        return eeIt->second;
    } else {
        return compileModule(func->getParent());
    }
}

llvm::ExecutionEngine *ExternalDispatcher::compileModule(llvm::Module *M) {
    assert(executionEngines.find(M) == executionEngines.end());

    std::string ErrStr;
    std::unique_ptr<llvm::Module> Owner(M);
    llvm::ExecutionEngine *EE = EngineBuilder(std::move(Owner)).setErrorStr(&ErrStr).create();

    if (!EE) {
        llvm::errs() << "unable to make jit: " << ErrStr << "\n";
        abort();
    }

    EE->finalizeObject();

    // Store this engine
    executionEngines[M] = EE;

    return EE;
}

llvm::Module *ExternalDispatcher::getModuleForNewFunction(const llvm::Function *F) {
    std::ostringstream oss;
    oss << "mcjit_mod__" << F->getName().str();

    Module *M = new Module(oss.str(), context);

    return M;
}
