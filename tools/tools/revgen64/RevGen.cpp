///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#include <lib/Utils/Utils.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>

#include <fstream>
#include <lib/Utils/BinaryCFGReader.h>

#include <lib/Utils/cfg.pb.h>

#include "InstructionLabeling.h"
#include "MemoryWrapperElimination.h"
#include "RegisterPromotion.h"
#include "RevGen.h"

using namespace llvm;
using namespace s2etools;

LogKey RevGen::TAG = LogKey("RevGen");

namespace {
cl::opt<std::string> BitcodeLibary("bitcodelib", cl::desc("Path to the bitcode library"), cl::Required);

cl::opt<std::string> BinaryFile("binary", cl::desc("The binary file to translate"), cl::Required);

cl::opt<std::string> OutputFile("output", cl::desc("Output bitcode file"), cl::Required);

cl::opt<std::string> McSemaCfg("mcsema-cfg", cl::desc("CFG in protobuf format"), cl::Required);

cl::opt<bool> GenTrace("gentrace", cl::desc("Generate tracing code for debugging"), cl::init(false), cl::Optional);

cl::opt<bool> DetectLibraryFunctions("detect-library-functions",
                                     cl::desc("Instrument the binary for runtime detection of library functions"),
                                     cl::init(false), cl::Optional);

cl::opt<bool> EraseTbFunctions("erase-tb-functions",
                               cl::desc("Remove needless translation block functions after code generation"),
                               cl::init(false), cl::Optional);

cl::opt<std::string> FunctionsToRevgen("functions-to-revgen", cl::desc("Only translate the given functions"),
                                       cl::Optional);
} // namespace

RevGen::~RevGen() {
    if (m_translator) {
        delete m_translator;
    }
}

bool RevGen::initialize(void) {
    m_fp = vmi::FileSystemFileProvider::get(m_binaryFile, false);
    if (!m_fp) {
        llvm::errs() << "Can't open " << m_binaryFile << "\n";
        return false;
    }

    m_binary = vmi::ExecutableFile::get(m_fp, false, 0);
    if (!m_binary) {
        llvm::errs() << "Can't parse " << m_binaryFile << "\n";
        return false;
    }

    LOGINFO("ImageBase: " << hexval(m_binary->getImageBase()) << "\n");

    m_translator = new X86Translator(m_bitcodeLibrary, m_binary);

    return true;
}

TranslatedBlock *RevGen::translate(uint64_t start, uint64_t end) {
    LOGDEBUG("========================================\n");
    LOGDEBUG("Translating: " << hexval(start) << " to " << hexval(end) << "\n");

    TranslatedBlock *tb = m_translator->translate(start, end);
    if (!tb) {
        LOGERROR("Could not translate block\n");
        return NULL;
    }

    if (tb->getType() == BB_EXCP) {
        LOGERROR("BB contains invalid instruction\n");
    }

    LOGDEBUG(*tb->getFunction() << "\n");
    return tb;
}

Constant *RevGen::injectDataSection(const std::string &name, uint64_t va, uint8_t *data, unsigned size) {
    Module *m = m_translator->getModule();
    LLVMContext &ctx = m->getContext();

    LOGDEBUG("Section " << name << " va=" << hexval(va) << " size=" << hexval(size) << "\n");

    /* Inject the array */
    std::vector<Constant *> constants;
    for (unsigned i = 0; i < size; ++i) {
        constants.push_back(ConstantInt::get(m->getContext(), APInt(8, data[i])));
    }

    ArrayType *type = ArrayType::get(Type::getInt8Ty(m->getContext()), size);
    Constant *initializer = NULL;
    if (data) {
        initializer = ConstantArray::get(type, constants);
    } else {
        initializer = ConstantAggregateZero::get(type);
    }

    GlobalVariable *var = m->getGlobalVariable(name);
    assert(!var);
    var = new GlobalVariable(*m, type, false, llvm::GlobalVariable::PrivateLinkage, initializer, name);

    Constant *ptrToVar = ConstantExpr::getPointerCast(var, type->getPointerTo());
    llvm::SmallVector<Value *, 2> IdxList;
    IdxList.push_back(ConstantInt::get(IntegerType::get(ctx, 32), APInt(32, 0)));
    IdxList.push_back(ConstantInt::get(IntegerType::get(ctx, 32), APInt(32, 0)));
    initializer = ConstantExpr::getGetElementPtr(nullptr, ptrToVar, IdxList, true);

    return initializer;
}

void RevGen::InjectArray(Module *m, const std::string &ptrName, const std::string &arrName,
                         SmallVector<Constant *, 4> &arrValues) {
    LLVMContext &ctx = m->getContext();
    Constant *initializer = NULL;
    ArrayType *arrTy;
    Type *elTy = Type::getInt64Ty(ctx);

    if (arrValues.size() > 0) {
        elTy = arrValues[0]->getType();
    }

    arrTy = ArrayType::get(elTy, arrValues.size());
    initializer = ConstantArray::get(arrTy, arrValues);

    GlobalVariable *arr =
        new GlobalVariable(*m, arrTy, false, llvm::GlobalVariable::PrivateLinkage, initializer, arrName);

    Constant *ptrToVar = ConstantExpr::getPointerCast(arr, arrTy->getPointerTo());
    llvm::SmallVector<Value *, 2> IdxList;
    IdxList.push_back(ConstantInt::get(IntegerType::get(ctx, 32), APInt(32, 0)));
    IdxList.push_back(ConstantInt::get(IntegerType::get(ctx, 32), APInt(32, 0)));
    initializer = ConstantExpr::getGetElementPtr(nullptr, ptrToVar, IdxList, true);

    GlobalVariable *var = m->getGlobalVariable(ptrName);
    if (!var) {
        var = new GlobalVariable(*m, initializer->getType(), false, GlobalValue::ExternalLinkage, initializer, ptrName);
    }

    LOGDEBUG(*initializer << "\n");
    LOGDEBUG(*var << "\n");

    var->setInitializer(initializer);
}

void RevGen::injectSections() {
    LOGDEBUG("Injecting sections...\n");
    Module *m = m_translator->getModule();
    LLVMContext &ctx = m->getContext();

    const vmi::Sections &sections = m_binary->getSections();

    unsigned count = 0;
    ConstantInt *sectionCount = NULL;
    SmallVector<Constant *, 4> sectionAddresses;
    SmallVector<Constant *, 4> sectionSizes;
    SmallVector<Constant *, 4> sectionsInits;

    for (auto const &desc : sections) {
        LOGDEBUG(" Section " << desc.name << " va=" << hexval(desc.start) << " size=" << hexval(desc.size) << "\n");

        uint8_t *buf = new uint8_t[desc.virtualSize];
        memset(buf, 0, desc.virtualSize);

        ssize_t ret = m_binary->read(buf, desc.size, desc.start);
        if (ret != (ssize_t) desc.size) {
            LOGERROR("Could not read data from section " << desc.name << " (" << ret << ")\n");
        } else {
            Constant *s = injectDataSection(desc.name, desc.start, buf, desc.virtualSize);
            sectionsInits.push_back(s);

            sectionAddresses.push_back(ConstantInt::get(ctx, APInt(64, desc.start)));
            sectionSizes.push_back(ConstantInt::get(ctx, APInt(64, desc.virtualSize)));
            ++count;
        }

        delete[] buf;
    }

    sectionCount = ConstantInt::get(ctx, APInt(32, count));

    // Inject initializers
    GlobalVariable *varSectionCount = m->getGlobalVariable("section_count");
    assert(varSectionCount);
    varSectionCount->setInitializer(sectionCount);

    InjectArray(m, "section_vas", "__section_vas", sectionAddresses);
    InjectArray(m, "section_sizes", "__section_sizes", sectionSizes);
    InjectArray(m, "section_ptrs", "__section_ptrs", sectionsInits);
}

void RevGen::injectFunctionPointers() {
    Module *m = m_translator->getModule();
    LLVMContext &ctx = m->getContext();

    SmallVector<Constant *, 4> functionAddresses;
    SmallVector<Constant *, 4> functionPointers;

    for (auto const &func : m_llvmFunctions) {
        uint64_t pc = func.first;
        Function *f = func.second;

        functionAddresses.push_back(ConstantInt::get(ctx, APInt(64, pc)));
        functionPointers.push_back(f);
    }

    GlobalVariable *count = m->getGlobalVariable("revgen_function_count");
    assert(count);
    count->setInitializer(ConstantInt::get(ctx, APInt(64, functionAddresses.size())));

    InjectArray(m, "revgen_function_pointers", "__revgen_function_pointers", functionPointers);
    InjectArray(m, "revgen_function_addresses", "__revgen_function_addresses", functionAddresses);
}

llvm::Function *RevGen::createLLVMPrototype(BinaryFunction *bf) {
    SmallVector<Type *, 0> args;
    Module *m = m_translator->getModule();

    auto f = Function::Create(m_translator->getTbType(), Function::ExternalLinkage, bf->getName(), m);

    // Avoid naming collisions with libc
    std::stringstream ss;
    ss << "__revgen_" << f->getName().str() << "_" << std::hex << bf->getEntryBlock()->getStartPc();
    f->setName(ss.str());
    return f;
}

void RevGen::createFunctionPrototypes() {
    LOGDEBUG("Creating function prototypes\n");

    uint64_t entryPoint = m_binary->getEntryPoint();
    bool foundEntryPoint = false;

    for (auto const &bf : m_functions) {
        uint64_t start = bf->getEntryBlock()->getStartPc();
        Function *f;

        LOGDEBUG("  Found function " << bf->getName() << " address=" << hexval(start) << "\n");

        if (start == entryPoint) {
            const std::string revgen_entrypoint = "revgen_entrypoint";
            bf->rename(revgen_entrypoint);
            f = m_translator->getModule()->getFunction(revgen_entrypoint);
            if (!f) {
                LOGERROR(revgen_entrypoint << " could not be found in the bitcode library\n");
                exit(-1);
            }
            foundEntryPoint = true;
        } else {
            f = createLLVMPrototype(bf);
        }

        m_llvmFunctions[bf->getEntryBlock()->getStartPc()] = f;
    }

    if (!foundEntryPoint) {
        LOGERROR("Could not find entry point in binary\n");
        exit(-1);
    }
}

Function *RevGen::getCallMarker() {
    Module *m = m_translator->getModule();
    LLVMContext &c = m->getContext();

    llvm::SmallVector<Type *, 1> params;
    params.push_back(Type::getIntNTy(c, Translator::getTargetPtrSizeInBytes() * 8));
    FunctionType *ty = FunctionType::get(Type::getVoidTy(c), params, false);

    return dyn_cast<Function>(m->getOrInsertFunction("call_marker", ty).getCallee());
}

Function *RevGen::getIncompleteMarker() {
    Module *m = m_translator->getModule();
    LLVMContext &c = m->getContext();

    llvm::SmallVector<Type *, 1> params;
    params.push_back(Type::getIntNTy(c, Translator::getTargetPtrSizeInBytes() * 8));
    FunctionType *ty = FunctionType::get(Type::getVoidTy(c), params, false);

    return dyn_cast<Function>(m->getOrInsertFunction("incomplete_marker", ty).getCallee());
}

Function *RevGen::getTraceFunction() {
    Module *m = m_translator->getModule();
    LLVMContext &c = m->getContext();

    llvm::SmallVector<Type *, 1> params;
    params.push_back(Type::getIntNTy(c, Translator::getTargetPtrSizeInBytes() * 8));
    FunctionType *ty = FunctionType::get(Type::getVoidTy(c), params, false);

    return dyn_cast<Function>(m->getOrInsertFunction("revgen_trace", ty).getCallee());
}

void RevGen::generateTrace(llvm::IRBuilder<> &builder, uint64_t pc) {
    Module *m = m_translator->getModule();
    LLVMContext &c = m->getContext();

    Function *f = getTraceFunction();
    SmallVector<Value *, 1> args;

    unsigned bits = Translator::getTargetPtrSizeInBytes() * 8;
    ConstantInt *ci = ConstantInt::get(c, APInt(bits, pc));
    args.push_back(ci);
    builder.CreateCall(f, args);
}

void RevGen::generateIncompleteMarker(llvm::IRBuilder<> &builder, uint64_t pc) {
    Module *m = m_translator->getModule();
    LLVMContext &c = m->getContext();

    Function *f = getIncompleteMarker();
    SmallVector<Value *, 1> args;

    unsigned bits = Translator::getTargetPtrSizeInBytes() * 8;
    ConstantInt *ci = ConstantInt::get(c, APInt(bits, pc));
    args.push_back(ci);
    builder.CreateCall(f, args);
}

void RevGen::generateFunctionCall(TranslatedBlock *tb) {
    assert(tb->isCallInstruction());
    static std::set<uint64_t> nonExistingFunctions;

    /**
     * Retrieve the return instructions, before which
     * we'll place the call
     */
    Function *tbf = tb->getFunction();
    SmallVector<ReturnInst *, 2> ret;

    Translator::getRetInstructions(tbf, ret);
    assert(ret.size() == 1);

    ReturnInst *ri = ret[0];

    if (tb->getType() == BB_CALL) {
        uint64_t target = tb->getSuccessor(0);
        LOGDEBUG("  Target: " << hexval(target) << "\n");
        if (m_llvmFunctions.find(target) == m_llvmFunctions.end()) {
            if (nonExistingFunctions.find(target) == nonExistingFunctions.end()) {
                LOGERROR("  >Function " << hexval(target) << " does not exist\n");
                nonExistingFunctions.insert(target);
            }

            Function *incomplete = getIncompleteMarker();
            SmallVector<Value *, 1> args;

            unsigned bits = Translator::getTargetPtrSizeInBytes() * 8;
            ConstantInt *ci = ConstantInt::get(tbf->getParent()->getContext(), APInt(bits, target));
            args.push_back(ci);
            CallInst::Create(incomplete, args, "", ri);
            return;
        }

        Function *targetTb = m_llvmFunctions[target];

        llvm::SmallVector<Value *, 1> argValues;
        argValues.push_back(&*tbf->arg_begin());

        CallInst::Create(targetTb, ArrayRef<Value *>(argValues), "", ri);
    } else {
        Function *cm = getCallMarker();
        assert(ret.size() == 1);

        StoreInst *si = tb->getLastPcAssignment();

        SmallVector<Value *, 1> args;
        // XXX: hopefully this value is the latest one
        args.push_back(si->getValueOperand());
        CallInst::Create(cm, args, "", ri);
    }
}

void RevGen::generateIndirectJump(llvm::IRBuilder<> &builder, RevGen::LLVMBasicBlockMap &allBbs, uint64_t bbPc) {
    Module *m = m_translator->getModule();
    LLVMContext &ctx = m->getContext();
    Function *f = builder.GetInsertBlock()->getParent();

    BinaryBasicBlock *binBb = m_bbs.find(bbPc);
    assert(binBb);

    /**
     * Create a switch statement with all the possible target values.
     * We add a default target in case the recovered CFG was incomplete.
     */
    BasicBlock *defaultCase = BasicBlock::Create(ctx, "", f);
    IRBuilder<> dbuilder(defaultCase);
    generateIncompleteMarker(dbuilder, binBb->getEndPc());
    dbuilder.CreateRet(ConstantInt::get(ctx, APInt(64, 0)));

    /* Generate a program counter load */
    Value *gep = Translator::getPcPtr(builder);
    Value *pc = builder.CreateLoad(gep);

    SwitchInst *sw = builder.CreateSwitch(pc, defaultCase, binBb->numSuccessors());

    for (auto sit = binBb->succ_begin(); sit != binBb->succ_end(); ++sit) {
        BinaryBasicBlock *targetBinBb = *sit;
        LOGDEBUG("Succ: " << hexval(targetBinBb->getStartPc()) << "\n");

        LLVMBasicBlockMap::iterator it = allBbs.find(targetBinBb->getStartPc());
        if (it == allBbs.end()) {
            LOGERROR("   Could not find bb " << hexval(targetBinBb->getStartPc()) << "\n");
            // This is ok, will be handled by the default case (crash at runtime).
            continue;
        }

        BasicBlock *destBb = (*it).second;
        ConstantInt *ci = ConstantInt::get(ctx, APInt(Translator::getTargetPtrSizeInBytes() * 8, (*it).first));
        sw->addCase(ci, destBb);
    }
}

void RevGen::enableLibraryCallDetector() {
    Module *m = m_translator->getModule();
    std::string varName = "__revgen_detect_library_functions";
    GlobalVariable *var = m->getGlobalVariable(varName);
    LLVMContext &ctx = m->getContext();
    Type *ty = Type::getInt32Ty(ctx);
    Constant *initializer = ConstantInt::get(ty, APInt(32, 1));
    if (!var) {
        var = new GlobalVariable(*m, ty, false, GlobalValue::ExternalLinkage, initializer, varName);
    } else {
        if (var->getType() != ty) {
            LOGERROR(varName << " has invalid type " << *var->getType() << " expected " << *ty << "\n");
            exit(-1);
        }
        var->setInitializer(initializer);
    }
}

/* Remove all tcg-llvm-* functions */
void RevGen::eraseTbFunctions() {
    Module *m = m_translator->getModule();
    std::vector<Function *> f2erase;
    foreach2 (it, m->begin(), m->end()) {
        Function &f = *it;
        if (f.getName().startswith("tcg-llvm-tb-")) {
            f2erase.push_back(&f);
        }
    }

    for (auto f : f2erase) {
        f->eraseFromParent();
    }

    LOGINFO("Erased " << f2erase.size() << " tcg functions\n");
}

void RevGen::translate(const llvm::BinaryFunctions &functions, const llvm::BinaryBasicBlocks &bbs) {
    m_functions = functions;
    m_bbs = bbs;

    std::unordered_map<uint64_t, BinaryFunction *> fcnMap;
    for (auto fcn : functions) {
        fcnMap[fcn->getEntryBlock()->getStartPc()] = fcn;
    }

    for (auto const &bb : m_bbs) {
        TranslatedBlock *tb = translate(bb->getStartPc(), bb->getEndPc());
        if (tb) {
            m_tbs[tb->getAddress()] = tb;
        }
    }

    // Create dummy functions if there are calls to functions that are
    // not in the input CFG.
    for (const auto p : m_tbs) {
        auto tb = p.second;

        if (tb->getType() != BB_CALL) {
            continue;
        }

        uint64_t target = tb->getSuccessor(0);
        if (fcnMap.find(target) != fcnMap.end()) {
            continue;
        }

        const auto tit = m_tbs.find(target);
        if (tit == m_tbs.end()) {
            LOGWARNING("Could not find entry point " << hexval(target) << " for unknown function");
            continue;
        }

        auto ttb = tit->second;

        std::stringstream ss;
        ss << "__unk_fcn_" << hexval(target);
        BinaryFunction *newFcn = new BinaryFunction(ss.str());

        auto start = ttb->getAddress();
        auto end = ttb->getLastAddress();
        auto size = ttb->getSize();
        BinaryBasicBlock *newBb = new BinaryBasicBlock(start, end, size);
        newFcn->add(newBb);
        newFcn->setEntryBlock(newBb);
        m_functions.insert(newFcn);
        fcnMap[target] = newFcn;
    }

    createFunctionPrototypes();

    /* We need all tbs to be generated before patching them */
    for (auto const &_tb : m_tbs) {
        TranslatedBlock *tb = (_tb).second;
        if (tb->isCallInstruction()) {
            generateFunctionCall(tb);
        }
    }

    RegisterPromotion::Functions funcs;

    /* Stitch together all basic blocks */
    for (auto const &bf : m_functions) {
        Function *f = reconstructFunction(bf);
        /* Verify that the function is valid for LLVM */
        verifyFunction(*f);

        funcs.insert(f);
    }

    /* Put the data sections */
    injectSections();

    /* To resolve indirect calls at run time */
    injectFunctionPointers();

    /**
     * Inject set a global variables to enable
     * runtime library function detection.
     */
    if (DetectLibraryFunctions) {
        enableLibraryCallDetector();
    }

    if (EraseTbFunctions) {
        eraseTbFunctions();
    }

    /* Run optimizations */
    {
        legacy::PassManager PM;

        PM.add(new MemoryWrapperElimination());
        PM.add(llvm::createAlwaysInlinerLegacyPass());

        /**
         * This pass is broken, doesn't save registers
         * properly on subfunction call.
         */
        // PM.add(new RegisterPromotion(funcs));

        PM.add(createPromoteMemoryToRegisterPass());

        PM.run(*m_translator->getModule());
    }

#if 1
    {
        Module *m = m_translator->getModule();

        legacy::PassManager MPM;
        PassManagerBuilder pb;
        pb.OptLevel = 3;
        pb.populateModulePassManager(MPM);
        MPM.add(new MemoryWrapperElimination());

        /* LTO pass seems to delete everything for some reason */
        // pb.populateLTOPassManager(MPM, true, false);

        MPM.add(new InstructionLabeling());

        MPM.run(*m);
    }
#endif
}

Function *RevGen::reconstructFunction(BinaryFunction *bf) {
    uint64_t address = bf->getEntryBlock()->getStartPc();
    Function *f = m_llvmFunctions[address];
    assert(f);

    if (!f->empty()) {
        LOGERROR(*f);
    }
    assert(f->empty());

    /* Create initial BB */
    Module *m = m_translator->getModule();
    LLVMContext &ctx = m->getContext();
    BasicBlock *entryBlock = BasicBlock::Create(ctx, "", f);

    llvm::DenseMap<uint64_t, BasicBlock *> basicBlocks;

    IRBuilder<> builder(ctx);
    builder.SetInsertPoint(entryBlock);

    Value *arg = &*f->arg_begin();

    SmallVector<Value *, 1> args;
    args.push_back(arg);

    /* Create first all empty blocks */
    for (auto const &bb : *bf) {
        BasicBlock *fbb = BasicBlock::Create(ctx, "", f);
        basicBlocks[bb->getStartPc()] = fbb;
    }

    /* Jump to the real entry block */
    uint64_t entryPointAddress = bf->getEntryBlock()->getStartPc();
    BasicBlock *actualEntryBlock = basicBlocks[entryPointAddress];
    assert(actualEntryBlock);
    builder.CreateBr(actualEntryBlock);

    /* Insert calls to the actual basic block code */
    for (auto const &basicBlock : basicBlocks) {
        uint64_t address = basicBlock.first;
        BasicBlock *bb = basicBlock.second;
        assert(bb && "Null bb found");
        builder.SetInsertPoint(bb);

        TranslatedBlock *tb = m_tbs[address];
        if (!tb) {
            LOGERROR("Could not find bb at address " << hexval(address) << "\n");
            generateIncompleteMarker(builder, address);
            ConstantInt *ci = ConstantInt::get(ctx, APInt(64, 0));
            builder.CreateRet(ci);
            continue;
        }

        if (GenTrace) {
            generateTrace(builder, tb->getAddress());
        }

        Value *callResult = builder.CreateCall(tb->getFunction(), args);
        switch (tb->getType()) {
            case BB_CALL:
            case BB_CALL_IND:
            case BB_DEFAULT: {
                /* Fallback to the next instruction */
                uint64_t next = tb->getAddress() + tb->getSize();

                if (basicBlocks.find(next) == basicBlocks.end()) {
                    LOGERROR("Could not find target bb at address " << hexval(next) << "\n");
                    generateIncompleteMarker(builder, next);
                    builder.CreateRet(callResult);
                } else {
                    BasicBlock *tbb = basicBlocks[next];
                    builder.CreateBr(tbb);
                }
            } break;

            case BB_JMP: {
                /* Jump to the unique successor */
                if (basicBlocks.find(tb->getSuccessor(0)) == basicBlocks.end()) {
                    LOGWARNING("Basic block with direct jump " << hexval(tb->getAddress())
                                                               << " is missing its successor\n");
                    generateIncompleteMarker(builder, tb->getAddress() + tb->getSize());
                    builder.CreateRet(callResult);
                } else {
                    BasicBlock *tbb = basicBlocks[tb->getSuccessor(0)];
                    assert(tbb);
                    builder.CreateBr(tbb);
                }
            } break;

            case BB_JMP_IND: {
                generateIndirectJump(builder, basicBlocks, address);
            } break;

            case BB_REP:
            case BB_COND_JMP: {
                BasicBlock *trueBB = basicBlocks.count(tb->getSuccessor(0)) ? basicBlocks[tb->getSuccessor(0)] : NULL;
                BasicBlock *falseBB = basicBlocks.count(tb->getSuccessor(1)) ? basicBlocks[tb->getSuccessor(1)] : NULL;

                if (trueBB && falseBB) {
                    ConstantInt *ci = ConstantInt::get(ctx, APInt(64, tb->getSuccessor(0)));
                    Value *cond = builder.CreateICmpEQ(callResult, ci);
                    builder.CreateCondBr(cond, trueBB, falseBB);
                } else {
                    LOGWARNING("Basic block with conditional branch " << hexval(tb->getAddress())
                                                                      << " is missing one or more successors\n");
                    /* TODO: try to handle case where one target is valid */
                    generateIncompleteMarker(builder, tb->getAddress() + tb->getSize());
                    builder.CreateRet(callResult);
                }
            } break;

            case BB_RET: {
                builder.CreateRet(callResult);
            } break;

            case BB_COND_JMP_IND:
            default: {
                assert(false && "Unsupported block type");
            }
        }
    }

    return f;
}

void RevGen::writeBitcodeFile(const std::string &bitcodeFile) {
    std::error_code EC;
    llvm::raw_fd_ostream o(bitcodeFile, EC, llvm::sys::fs::F_None);

    llvm::Module *module = m_translator->getModule();

    // Output the bitcode file to stdout
    llvm::WriteBitcodeToFile(*module, o);
}

// This function can be called from GDB for debugging
void PrintValue(llvm::Value *v) {
    llvm::outs() << *v << "\n";
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " analysis");
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    if (!llvm::sys::fs::exists(BinaryFile)) {
        llvm::errs() << BinaryFile << " does not exist\n";
        return -1;
    }

    if (!llvm::sys::fs::exists(BitcodeLibary)) {
        llvm::errs() << BitcodeLibary << " does not exist\n";
        return -1;
    }

    RevGen translator(BinaryFile, BitcodeLibary);

    if (!translator.initialize()) {
        llvm::errs() << "Could not initialize translator\n";
        return -1;
    }

    BinaryBasicBlocks toTranslate;
    BinaryFunctions functions;

    if (llvm::sys::fs::exists(McSemaCfg)) {
        ParseMcSemaCfgFile(McSemaCfg, toTranslate, functions);
    } else {
        llvm::errs() << McSemaCfg << " does not exist\n";
        return -1;
    }

    if (!functions.size()) {
        llvm::errs() << "No functions to translate. Check the CFG file\n";
        return -1;
    }

    if (FunctionsToRevgen.size() > 0) {
        using namespace std;
        istringstream iss(FunctionsToRevgen);
        vector<string> tokens;
        copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter(tokens));

        std::set<uint64_t> pcs;
        for (string pc : tokens) {
            pcs.insert(strtol(pc.c_str(), NULL, 0));
        }

        BinaryFunctions tokeep;
        bool foundEp = false;
        for (BinaryFunction *f : functions) {
            uint64_t spc = f->getEntryBlock()->getStartPc();
            if (spc == translator.getBinary()->getEntryPoint()) {
                tokeep.insert(f);
                foundEp = true;
            } else if (pcs.find(spc) == pcs.end()) {
                delete f;
            } else {
                tokeep.insert(f);
            }
        }

        if (!foundEp) {
            llvm::errs() << "Could not find entry point\n";
            return -1;
        }

        if (tokeep.size() != pcs.size() + 1) {
            llvm::errs() << "Could not find some functions\n";
            return -1;
        }

        functions = tokeep;
    }

    if (!toTranslate.size()) {
        llvm::errs() << "No basic blocks to translate. Check the CFG file\n";
        return -1;
    }

    translator.translate(functions, toTranslate);
    translator.writeBitcodeFile(OutputFile);

    return 0;
}
