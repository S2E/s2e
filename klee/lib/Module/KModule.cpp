//===-- KModule.cpp -------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// FIXME: This does not belong here.
#include "klee/Common.h"

#include "klee/Internal/Module/KModule.h"

#include "Passes.h"

#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Interpreter.h"

#include <klee/Context.h>

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/ValueSymbolTable.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/Scalarizer.h"
#include "llvm/Transforms/Utils.h"

#include <sstream>

using namespace llvm;
using namespace klee;

namespace {
enum SwitchImplType { eSwitchTypeSimple, eSwitchTypeLLVM, eSwitchTypeInternal };

cl::list<std::string> MergeAtExit("merge-at-exit");

cl::opt<bool> NoTruncateSourceLines("no-truncate-source-lines",
                                    cl::desc("Don't truncate long lines in the output source"));

cl::opt<bool> OutputSource("output-source", cl::desc("Write the assembly for the final transformed source"),
                           cl::init(true));

cl::opt<bool> OutputModule("output-module", cl::desc("Write the bitcode for the final transformed module"),
                           cl::init(false));

cl::opt<SwitchImplType> SwitchType("switch-type", cl::desc("Select the implementation of switch"),
                                   cl::values(clEnumValN(eSwitchTypeSimple, "simple", "lower to ordered branches"),
                                              clEnumValN(eSwitchTypeLLVM, "llvm", "lower using LLVM"),
                                              clEnumValN(eSwitchTypeInternal, "internal", "execute switch internally")),
                                   cl::init(eSwitchTypeInternal));

cl::opt<bool> DebugPrintEscapingFunctions("debug-print-escaping-functions",
                                          cl::desc("Print functions whose address is taken."));
} // namespace

KModule::KModule(Module *_module)
    : module(_module), dataLayout(new DataLayout(module)), dbgStopPointFn(0), kleeMergeFn(0) {
}

KModule::~KModule() {

    for (std::vector<KFunction *>::iterator it = functions.begin(), ie = functions.end(); it != ie; ++it)
        delete *it;

    delete dataLayout;

    // XXX: S2E: we use the module outside, so do not delete it here.
    // delete module;
}

/***/

namespace llvm {
extern void Optimize(Module *);
}

// what a hack
static Function *getStubFunctionForCtorList(Module *m, GlobalVariable *gv, std::string name) {
    assert(!gv->isDeclaration() && !gv->hasInternalLinkage() &&
           "do not support old LLVM style constructor/destructor lists");

    llvm::ArrayRef<Type *> nullary(NULL, (size_t) 0);
    LLVMContext &context = m->getContext();

    Function *fn = Function::Create(FunctionType::get(Type::getVoidTy(context), nullary, false),
                                    GlobalVariable::InternalLinkage, name, m);
    BasicBlock *bb = BasicBlock::Create(context, "entry", fn);

    // From lli:
    // Should be an array of '{ int, void ()* }' structs.  The first value is
    // the init priority, which we ignore.
    ConstantArray *arr = dyn_cast<ConstantArray>(gv->getInitializer());
    if (arr) {
        for (unsigned i = 0; i < arr->getNumOperands(); i++) {
            ConstantStruct *cs = cast<ConstantStruct>(arr->getOperand(i));
            // There is a third *optional* element in global_ctor elements (``i8
            // @data``).
            assert((cs->getNumOperands() == 2 || cs->getNumOperands() == 3) &&
                   "unexpected element in ctor initializer list");

            Constant *fp = cs->getOperand(1);
            if (!fp->isNullValue()) {
                if (llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(fp))
                    fp = ce->getOperand(0);

                if (Function *f = dyn_cast<Function>(fp)) {
                    CallInst::Create(f, "", bb);
                } else {
                    pabort("unable to get function pointer from ctor initializer list");
                }
            }
        }
    }

    ReturnInst::Create(context, bb);

    return fn;
}

static void injectStaticConstructorsAndDestructors(Module *m) {
    GlobalVariable *ctors = m->getNamedGlobal("llvm.global_ctors");
    GlobalVariable *dtors = m->getNamedGlobal("llvm.global_dtors");

    if (ctors || dtors) {
        Function *mainFn = m->getFunction("main");
        assert(mainFn && "unable to find main function");

        if (ctors)
            CallInst::Create(getStubFunctionForCtorList(m, ctors, "klee.ctor_stub"), "", &*mainFn->begin()->begin());
        if (dtors) {
            Function *dtorStub = getStubFunctionForCtorList(m, dtors, "klee.dtor_stub");
            for (Function::iterator it = mainFn->begin(), ie = mainFn->end(); it != ie; ++it) {
                if (isa<ReturnInst>(it->getTerminator()))
                    CallInst::Create(dtorStub, "", it->getTerminator());
            }
        }
    }
}

static void forceImport(Module *m, const char *name, Type *retType, ...) {
    // If module lacks an externally visible symbol for the name then we
    // need to create one. We have to look in the symbol table because
    // we want to check everything (global variables, functions, and
    // aliases).

    Value *v = m->getValueSymbolTable().lookup(name);
    GlobalValue *gv = dyn_cast_or_null<GlobalValue>(v);

    if (!gv || gv->hasInternalLinkage()) {
        va_list ap;

        va_start(ap, retType);
        std::vector<Type *> argTypes;
        while (Type *t = va_arg(ap, Type *))
            argTypes.push_back(t);
        va_end(ap);

        ArrayRef<Type *> argTypesA(argTypes);

        m->getOrInsertFunction(name, FunctionType::get(retType, argTypesA, false));
    }
}

#ifdef __MINGW32__
static const char *index(const char *str, char c) {
    while (*str) {
        if (*str == c) {
            return str;
        }
        ++str;
    }
    return NULL;
}
#endif

void KModule::prepare(const Interpreter::ModuleOptions &opts, InterpreterHandler *ih) {
    LLVMContext &context = module->getContext();

    if (!MergeAtExit.empty()) {
        Function *mergeFn = module->getFunction("klee_merge");
        if (!mergeFn) {
            llvm::FunctionType *Ty =
                FunctionType::get(Type::getVoidTy(context), ArrayRef<Type *>(std::vector<Type *>()), false);
            mergeFn = Function::Create(Ty, GlobalVariable::ExternalLinkage, "klee_merge", module);
        }

        for (cl::list<std::string>::iterator it = MergeAtExit.begin(), ie = MergeAtExit.end(); it != ie; ++it) {
            std::string &name = *it;
            Function *f = module->getFunction(name);
            if (!f) {
                klee_error("cannot insert merge-at-exit for: %s (cannot find)", name.c_str());
            } else if (f->isDeclaration()) {
                klee_error("cannot insert merge-at-exit for: %s (external)", name.c_str());
            }

            BasicBlock *exit = BasicBlock::Create(context, "exit", f);
            PHINode *result = 0;
            if (f->getReturnType() != Type::getVoidTy(context))
                result = PHINode::Create(f->getReturnType(), 0, "retval", exit);
            CallInst::Create(mergeFn, "", exit);
            ReturnInst::Create(context, result, exit);

            llvm::errs() << "KLEE: adding klee_merge at exit of: " << name << "\n";
            for (llvm::Function::iterator bbit = f->begin(), bbie = f->end(); bbit != bbie; ++bbit) {
                if (&*bbit != exit) {
                    Instruction *i = bbit->getTerminator();
                    if (i->getOpcode() == Instruction::Ret) {
                        if (result) {
                            result->addIncoming(i->getOperand(0), &*bbit);
                        }
                        i->eraseFromParent();
                        BranchInst::Create(exit, &*bbit);
                    }
                }
            }
        }
    }

    // Inject checks prior to optimization... we also perform the
    // invariant transformations that we will end up doing later so that
    // optimize is seeing what is as close as possible to the final
    // module.
    legacy::PassManager pm;
    pm.add(new RaiseAsmPass());

    // This pass will scalarize as much code as possible so that the Executor
    // does not need to handle operands of vector type for most instructions
    // other than InsertElementInst and ExtractElementInst.
    //
    // NOTE: Must come before division/overshift checks because those passes
    // don't know how to handle vector instructions.
    pm.add(createScalarizerPass());

    // FIXME: This false here is to work around a bug in
    // IntrinsicLowering which caches values which may eventually be
    // deleted (via RAUW). This can be removed once LLVM fixes this
    // issue.
    pm.add(new IntrinsicCleanerPass(*dataLayout, false));
    pm.run(*module);

    if (opts.Optimize)
        Optimize(module);

    // Force importing functions required by intrinsic lowering. Kind of
    // unfortunate clutter when we don't need them but we won't know
    // that until after all linking and intrinsic lowering is
    // done. After linking and passes we just try to manually trim these
    // by name. We only add them if such a function doesn't exist to
    // avoid creating stale uses.

    llvm::Type *i8Ty = Type::getInt8Ty(context);
    forceImport(module, "memcpy", PointerType::getUnqual(i8Ty), PointerType::getUnqual(i8Ty),
                PointerType::getUnqual(i8Ty), dataLayout->getIntPtrType(context), (Type *) 0);
    forceImport(module, "memmove", PointerType::getUnqual(i8Ty), PointerType::getUnqual(i8Ty),
                PointerType::getUnqual(i8Ty), dataLayout->getIntPtrType(context), (Type *) 0);
    forceImport(module, "memset", PointerType::getUnqual(i8Ty), PointerType::getUnqual(i8Ty), Type::getInt32Ty(context),
                dataLayout->getIntPtrType(context), (Type *) 0);

    // FIXME: Missing force import for various math functions.

    // FIXME: Find a way that we can test programs without requiring
    // this to be linked in, it makes low level debugging much more
    // annoying.
    linkLibraries(opts);

    // Needs to happen after linking (since ctors/dtors can be modified)
    // and optimization (since global optimization can rewrite lists).
    injectStaticConstructorsAndDestructors(module);

    // Finally, run the passes that maintain invariants we expect during
    // interpretation. We run the intrinsic cleaner just in case we
    // linked in something with intrinsics but any external calls are
    // going to be unresolved. We really need to handle the intrinsics
    // directly I think?
    legacy::PassManager pm3;

    // the additional linked in libraries may also have vector instructions
    // so run ScalarizerPass once again to make sure of vector instr cleaned up
    pm3.add(createScalarizerPass());
    pm3.add(createCFGSimplificationPass());
    switch (SwitchType) {
        case eSwitchTypeInternal:
            break;
        case eSwitchTypeSimple:
            pm3.add(new LowerSwitchPass());
            break;
        case eSwitchTypeLLVM:
            pm3.add(createLowerSwitchPass());
            break;
        default:
            klee_error("invalid --switch-type");
    }
    InstructionOperandTypeCheckPass *operandTypeCheckPass = new InstructionOperandTypeCheckPass();
    pm3.add(new IntrinsicCleanerPass(*dataLayout));
    pm3.add(new PhiCleanerPass());
    pm3.add(operandTypeCheckPass);
    pm3.run(*module);

    // Enforce the operand type invariants that the Executor expects.  This
    // implicitly depends on the "Scalarizer" pass to be run in order to succeed
    // in the presence of vector instructions.
    if (!operandTypeCheckPass->checkPassed()) {
        klee_error("Unexpected instruction operand types detected");
    }

    // For cleanliness see if we can discard any of the functions we
    // forced to import.
    Function *f;
    f = module->getFunction("memcpy");
    if (f && f->use_empty())
        f->eraseFromParent();
    f = module->getFunction("memmove");
    if (f && f->use_empty())
        f->eraseFromParent();
    f = module->getFunction("memset");
    if (f && f->use_empty())
        f->eraseFromParent();

    // Write out the .ll assembly file. We truncate long lines to work
    // around a kcachegrind parsing bug (it puts them on new lines), so
    // that source browsing works.
    if (OutputSource) {
        llvm::raw_ostream *os = ih->openOutputFile("assembly.ll");
        assert(os && "unable to open source output");

        llvm::raw_ostream *ros = os;

        // We have an option for this in case the user wants a .ll they
        // can compile.
        if (NoTruncateSourceLines) {
            *ros << *module;
        } else {
            bool truncated = false;
            std::string string;
            llvm::raw_string_ostream rss(string);
            rss << *module;
            rss.flush();
            const char *position = string.c_str();

            for (;;) {
                const char *end = index(position, '\n');
                if (!end) {
                    *ros << position;
                    break;
                } else {
                    unsigned count = (end - position) + 1;
                    if (count < 255) {
                        ros->write(position, count);
                    } else {
                        ros->write(position, 254);
                        *ros << "\n";
                        truncated = true;
                    }
                    position = end + 1;
                }
            }
        }

        delete os;
    }

    if (OutputModule) {
        llvm::raw_ostream *f = ih->openOutputFile("final.bc");
        WriteBitcodeToFile(*module, *f);
        delete f;
    }

    dbgStopPointFn = module->getFunction("llvm.dbg.stoppoint");
    kleeMergeFn = module->getFunction("klee_merge");

    buildShadowStructures();
}

void KModule::linkLibraries(const Interpreter::ModuleOptions &opts) {
    for (std::vector<std::string>::const_iterator it = opts.ExtraLibraries.begin(), ie = opts.ExtraLibraries.end();
         it != ie; ++it) {
        module = linkWithLibrary(module, *it);
    }
}

void KModule::buildShadowStructures() {
    /* Build shadow structures */

    for (Module::iterator it = module->begin(), ie = module->end(); it != ie; ++it) {
        if (it->isDeclaration())
            continue;

        /* If the functions are from the persistent TB cache, build
         the shadow structures lazily, when we actually need them */
        if ((*it).getName().find("tcg-llvm-tb-") != std::string::npos) {
            continue;
        }

        KFunction *kf = new KFunction(&*it, this);

        functions.push_back(kf);
        functionMap.insert(std::make_pair(&*it, kf));
    }

    /* Compute various interesting properties */

    for (std::vector<KFunction *>::iterator it = functions.begin(), ie = functions.end(); it != ie; ++it) {
        KFunction *kf = *it;
        if (functionEscapes(kf->function))
            escapingFunctions.insert(kf->function);
    }

    if (DebugPrintEscapingFunctions && !escapingFunctions.empty()) {
        llvm::errs() << "KLEE: escaping functions: [";
        for (std::set<Function *>::iterator it = escapingFunctions.begin(), ie = escapingFunctions.end(); it != ie;
             ++it) {
            llvm::errs() << (*it)->getName() << ", ";
        }
        llvm::errs() << "]\n";
    }
}

KFunction *KModule::updateModuleWithFunction(llvm::Function *f) {
    assert(functionMap.find(f) == functionMap.end());

    KFunction *kf = new KFunction(f, this);

    functions.push_back(kf);
    functionMap.insert(std::make_pair(f, kf));

    if (functionEscapes(kf->function))
        escapingFunctions.insert(kf->function);

    return kf;
}

void KModule::removeFunction(llvm::Function *f, bool keepDeclaration) {
    std::map<llvm::Function *, KFunction *>::iterator it = functionMap.find(f);
    assert(it != functionMap.end());

    KFunction *kf = it->second;
    functions.erase(std::find(functions.begin(), functions.end(), kf));
    escapingFunctions.erase(f);
    functionMap.erase(f);
    delete kf;

    if (keepDeclaration) {
        f->deleteBody();
    } else {
        f->eraseFromParent();
    }
}

KConstant *KModule::getKConstant(const Constant *c) {
    auto it = constantMap.find(c);
    if (it != constantMap.end())
        return it->second;
    return NULL;
}

unsigned KModule::getConstantID(Constant *c, KInstruction *ki) {
    KConstant *kc = getKConstant(c);
    if (kc)
        return kc->id;

    unsigned id = constants.size();
    kc = new KConstant(c, id, ki);
    constantMap.insert(std::make_pair(c, kc));
    constants.push_back(c);
    return id;
}

Expr::Width KModule::getWidthForLLVMType(llvm::Type *type) const {
    return dataLayout->getTypeSizeInBits(type);
}

ref<klee::ConstantExpr> KModule::evalConstant(const GlobalAddresses &globalAddresses, const Constant *c,
                                              const KInstruction *ki) {
    if (!ki) {
        KConstant *kc = getKConstant(c);
        if (kc)
            ki = kc->ki;
    }

    if (const llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(c)) {
        return evalConstantExpr(globalAddresses, ce, ki);
    } else {
        if (const ConstantInt *ci = dyn_cast<ConstantInt>(c)) {
            return ConstantExpr::alloc(ci->getValue());
        } else if (const ConstantFP *cf = dyn_cast<ConstantFP>(c)) {
            return ConstantExpr::alloc(cf->getValueAPF().bitcastToAPInt());
        } else if (const GlobalValue *gv = dyn_cast<GlobalValue>(c)) {
            return globalAddresses.find(gv)->second;
        } else if (isa<ConstantPointerNull>(c)) {
            return Expr::createPointer(0);
        } else if (isa<UndefValue>(c) || isa<ConstantAggregateZero>(c)) {
            if (getWidthForLLVMType(c->getType()) == 0) {
                if (isa<llvm::LandingPadInst>(ki->inst)) {
                    klee_warning_once(0, "Using zero size array fix for landingpad instruction filter");
                    return ConstantExpr::create(0, 1);
                }
            }
            return ConstantExpr::create(0, getWidthForLLVMType(c->getType()));
        } else if (const ConstantDataSequential *cds = dyn_cast<ConstantDataSequential>(c)) {
            // Handle a vector or array: first element has the smallest address,
            // the last element the highest
            std::vector<ref<Expr>> kids;
            for (unsigned i = cds->getNumElements(); i != 0; --i) {
                ref<Expr> kid = evalConstant(globalAddresses, cds->getElementAsConstant(i - 1), ki);
                kids.push_back(kid);
            }
            assert(Context::get().isLittleEndian() && "FIXME:Broken for big endian");
            ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
            return cast<ConstantExpr>(res);
        } else if (const ConstantStruct *cs = dyn_cast<ConstantStruct>(c)) {
            const StructLayout *sl = dataLayout->getStructLayout(cs->getType());
            llvm::SmallVector<ref<Expr>, 4> kids;
            for (unsigned i = cs->getNumOperands(); i != 0; --i) {
                unsigned op = i - 1;
                ref<Expr> kid = evalConstant(globalAddresses, cs->getOperand(op), ki);

                uint64_t thisOffset = sl->getElementOffsetInBits(op),
                         nextOffset = (op == cs->getNumOperands() - 1) ? sl->getSizeInBits()
                                                                       : sl->getElementOffsetInBits(op + 1);
                if (nextOffset - thisOffset > kid->getWidth()) {
                    uint64_t paddingWidth = nextOffset - thisOffset - kid->getWidth();
                    kids.push_back(ConstantExpr::create(0, paddingWidth));
                }

                kids.push_back(kid);
            }
            assert(Context::get().isLittleEndian() && "FIXME:Broken for big endian");
            ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
            return cast<ConstantExpr>(res);
        } else if (const ConstantArray *ca = dyn_cast<ConstantArray>(c)) {
            llvm::SmallVector<ref<Expr>, 4> kids;
            for (unsigned i = ca->getNumOperands(); i != 0; --i) {
                unsigned op = i - 1;
                ref<Expr> kid = evalConstant(globalAddresses, ca->getOperand(op), ki);
                kids.push_back(kid);
            }
            assert(Context::get().isLittleEndian() && "FIXME:Broken for big endian");
            ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
            return cast<ConstantExpr>(res);
        } else if (const ConstantVector *cv = dyn_cast<ConstantVector>(c)) {
            llvm::SmallVector<ref<Expr>, 8> kids;
            const size_t numOperands = cv->getNumOperands();
            kids.reserve(numOperands);
            for (unsigned i = numOperands; i != 0; --i) {
                kids.push_back(evalConstant(globalAddresses, cv->getOperand(i - 1), ki));
            }
            assert(Context::get().isLittleEndian() && "FIXME:Broken for big endian");
            ref<Expr> res = ConcatExpr::createN(numOperands, kids.data());
            assert(isa<ConstantExpr>(res) && "result of constant vector built is not a constant");
            return cast<ConstantExpr>(res);
        } else if (const BlockAddress *ba = dyn_cast<BlockAddress>(c)) {
            // return the address of the specified basic block in the specified function
            const auto arg_bb = (BasicBlock *) ba->getOperand(1);
            const auto res = Expr::createPointer(reinterpret_cast<std::uint64_t>(arg_bb));
            return cast<ConstantExpr>(res);
        } else {
            std::string msg("Cannot handle constant ");
            llvm::raw_string_ostream os(msg);
            klee_error("%s", os.str().c_str());
        }
    }
}

klee::ref<klee::ConstantExpr> KModule::evalConstantExpr(const GlobalAddresses &globalAddresses,
                                                        const llvm::ConstantExpr *ce, const KInstruction *ki) {
    llvm::Type *type = ce->getType();

    ref<ConstantExpr> op1(0), op2(0), op3(0);
    int numOperands = ce->getNumOperands();

    if (numOperands > 0)
        op1 = evalConstant(globalAddresses, ce->getOperand(0), ki);
    if (numOperands > 1)
        op2 = evalConstant(globalAddresses, ce->getOperand(1), ki);
    if (numOperands > 2)
        op3 = evalConstant(globalAddresses, ce->getOperand(2), ki);

    /* Checking for possible errors during constant folding */
    switch (ce->getOpcode()) {
        case Instruction::SDiv:
        case Instruction::UDiv:
        case Instruction::SRem:
        case Instruction::URem:
            if (op2->getLimitedValue() == 0) {
                std::string msg("Division/modulo by zero during constant folding at location ");
                llvm::raw_string_ostream os(msg);
                klee_error("%s", os.str().c_str());
            }
            break;
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
            if (op2->getLimitedValue() >= op1->getWidth()) {
                std::string msg("Overshift during constant folding at location ");
                llvm::raw_string_ostream os(msg);
                klee_error("%s", os.str().c_str());
            }
    }

    std::string msg("Unknown ConstantExpr type");
    llvm::raw_string_ostream os(msg);

    switch (ce->getOpcode()) {
        default:
            klee_error("%s", os.str().c_str());

        case Instruction::Trunc:
            return op1->Extract(0, getWidthForLLVMType(type));
        case Instruction::ZExt:
            return op1->ZExt(getWidthForLLVMType(type));
        case Instruction::SExt:
            return op1->SExt(getWidthForLLVMType(type));
        case Instruction::Add:
            return op1->Add(op2);
        case Instruction::Sub:
            return op1->Sub(op2);
        case Instruction::Mul:
            return op1->Mul(op2);
        case Instruction::SDiv:
            return op1->SDiv(op2);
        case Instruction::UDiv:
            return op1->UDiv(op2);
        case Instruction::SRem:
            return op1->SRem(op2);
        case Instruction::URem:
            return op1->URem(op2);
        case Instruction::And:
            return op1->And(op2);
        case Instruction::Or:
            return op1->Or(op2);
        case Instruction::Xor:
            return op1->Xor(op2);
        case Instruction::Shl:
            return op1->Shl(op2);
        case Instruction::LShr:
            return op1->LShr(op2);
        case Instruction::AShr:
            return op1->AShr(op2);
        case Instruction::BitCast:
            return op1;

        case Instruction::IntToPtr:
            return op1->ZExt(getWidthForLLVMType(type));

        case Instruction::PtrToInt:
            return op1->ZExt(getWidthForLLVMType(type));

        case Instruction::GetElementPtr: {
            ref<ConstantExpr> base = op1->ZExt(Context::get().getPointerWidth());
            for (gep_type_iterator ii = gep_type_begin(ce), ie = gep_type_end(ce); ii != ie; ++ii) {
                ref<ConstantExpr> indexOp = evalConstant(globalAddresses, cast<Constant>(ii.getOperand()), ki);
                if (indexOp->isZero())
                    continue;

                // Handle a struct index, which adds its field offset to the pointer.
                if (auto STy = ii.getStructTypeOrNull()) {
                    unsigned ElementIdx = indexOp->getZExtValue();
                    const StructLayout *SL = dataLayout->getStructLayout(STy);
                    base = base->Add(
                        ConstantExpr::alloc(APInt(Context::get().getPointerWidth(), SL->getElementOffset(ElementIdx))));
                    continue;
                }

                // For array or vector indices, scale the index by the size of the type.
                // Indices can be negative
                base =
                    base->Add(indexOp->SExt(Context::get().getPointerWidth())
                                  ->Mul(ConstantExpr::alloc(APInt(Context::get().getPointerWidth(),
                                                                  dataLayout->getTypeAllocSize(ii.getIndexedType())))));
            }
            return base;
        }

        case Instruction::ICmp: {
            switch (ce->getPredicate()) {
                default:
                    assert(0 && "unhandled ICmp predicate");
                case ICmpInst::ICMP_EQ:
                    return op1->Eq(op2);
                case ICmpInst::ICMP_NE:
                    return op1->Ne(op2);
                case ICmpInst::ICMP_UGT:
                    return op1->Ugt(op2);
                case ICmpInst::ICMP_UGE:
                    return op1->Uge(op2);
                case ICmpInst::ICMP_ULT:
                    return op1->Ult(op2);
                case ICmpInst::ICMP_ULE:
                    return op1->Ule(op2);
                case ICmpInst::ICMP_SGT:
                    return op1->Sgt(op2);
                case ICmpInst::ICMP_SGE:
                    return op1->Sge(op2);
                case ICmpInst::ICMP_SLT:
                    return op1->Slt(op2);
                case ICmpInst::ICMP_SLE:
                    return op1->Sle(op2);
            }
        }

        case Instruction::Select:
            return op1->isTrue() ? op2 : op3;

        case Instruction::FAdd:
        case Instruction::FSub:
        case Instruction::FMul:
        case Instruction::FDiv:
        case Instruction::FRem:
        case Instruction::FPTrunc:
        case Instruction::FPExt:
        case Instruction::UIToFP:
        case Instruction::SIToFP:
        case Instruction::FPToUI:
        case Instruction::FPToSI:
        case Instruction::FCmp:
            assert(0 && "floating point ConstantExprs unsupported");
    }
    llvm_unreachable("Unsupported expression in evalConstantExpr");
    return op1;
}

/***/

KConstant::KConstant(llvm::Constant *_ct, unsigned _id, KInstruction *_ki) {
    ct = _ct;
    id = _id;
    ki = _ki;
}

/***/

static int getOperandNum(Value *v, std::map<Instruction *, unsigned> &registerMap, KModule *km, KInstruction *ki) {
    if (Instruction *inst = dyn_cast<Instruction>(v)) {
        return registerMap[inst];
    } else if (Argument *a = dyn_cast<Argument>(v)) {
        return a->getArgNo();
    } else if (isa<BasicBlock>(v) || isa<InlineAsm>(v)) {
        return -1;
    } else {
        assert(isa<Constant>(v));
        Constant *c = cast<Constant>(v);
        return -(km->getConstantID(c, ki) + 2);
    }
}

KFunction::KFunction(llvm::Function *_function, KModule *km)
    : function(_function), numArgs(function->arg_size()), numInstructions(0), trackCoverage(true) {

    legacy::FunctionPassManager pm(_function->getParent());
    pm.add(new IntrinsicFunctionCleanerPass());
    pm.run(*_function);

    for (llvm::Function::iterator bbit = function->begin(), bbie = function->end(); bbit != bbie; ++bbit) {
        BasicBlock *bb = &*bbit;
        basicBlockEntry[bb] = numInstructions;
        numInstructions += bb->size();
    }

    instructions = new KInstruction *[numInstructions];

    std::map<Instruction *, unsigned> registerMap;

    // The first arg_size() registers are reserved for formals.
    unsigned rnum = numArgs;
    for (llvm::Function::iterator bbit = function->begin(), bbie = function->end(); bbit != bbie; ++bbit) {
        for (llvm::BasicBlock::iterator it = bbit->begin(), ie = bbit->end(); it != ie; ++it)
            registerMap[&*it] = rnum++;
    }
    numRegisters = rnum;

    unsigned i = 0;
    for (llvm::Function::iterator bbit = function->begin(), bbie = function->end(); bbit != bbie; ++bbit) {
        for (llvm::BasicBlock::iterator it = bbit->begin(), ie = bbit->end(); it != ie; ++it) {
            KInstruction *ki;

            switch (it->getOpcode()) {
                case Instruction::GetElementPtr:
                case Instruction::InsertValue:
                case Instruction::ExtractValue:
                    ki = new KGEPInstruction();
                    break;

                case Instruction::Call:
                case Instruction::Invoke:
                    ki = new KCallInstruction();
                    break;

                default:
                    ki = new KInstruction();
                    break;
            }

            ki->inst = &*it;
            ki->dest = registerMap[&*it];

            if (isa<CallInst>(it) || isa<InvokeInst>(it)) {
                CallSite cs(&*it);
                unsigned numArgs = cs.arg_size();
                ki->operands = new int[numArgs + 1];
                ki->operands[0] = getOperandNum(cs.getCalledValue(), registerMap, km, ki);
                for (unsigned j = 0; j < numArgs; j++) {
                    Value *v = cs.getArgument(j);
                    ki->operands[j + 1] = getOperandNum(v, registerMap, km, ki);
                }
            } else {
                unsigned numOperands = it->getNumOperands();
                ki->operands = new int[numOperands];
                for (unsigned j = 0; j < numOperands; j++) {
                    Value *v = it->getOperand(j);

                    if (Instruction *inst = dyn_cast<Instruction>(v)) {
                        ki->operands[j] = registerMap[inst];
                    } else if (Argument *a = dyn_cast<Argument>(v)) {
                        ki->operands[j] = a->getArgNo();
                    } else if (isa<BasicBlock>(v) || isa<InlineAsm>(v) || isa<MDNode>(ValueAsMetadata::get(v))) {
                        ki->operands[j] = -1;
                    } else {
                        assert(isa<Constant>(v));
                        Constant *c = cast<Constant>(v);
                        ki->operands[j] = -(km->getConstantID(c, ki) + 2);
                    }
                }
            }

            ki->owner = this;
            instructions[i++] = ki;
            instrMap.insert(std::make_pair(&*it, ki));
        }
    }
}

KFunction::~KFunction() {
    for (unsigned i = 0; i < numInstructions; ++i)
        delete instructions[i];
    delete[] instructions;
}
