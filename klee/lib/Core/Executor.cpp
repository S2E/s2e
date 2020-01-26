//===-- Executor.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/Executor.h"

#include "klee/BitfieldSimplifier.h"
#include "klee/Context.h"
#include "klee/CoreStats.h"
#include "klee/ExternalDispatcher.h"
#include "klee/Memory.h"
#include "klee/PTree.h"
#include "klee/Searcher.h"
#include "klee/SolverFactory.h"
#include "klee/SolverManager.h"
#include "klee/SolverStats.h"
#include "klee/StatsTracker.h"
#include "klee/TimingSolver.h"
#include "klee/UserSearcher.h"
#include "SpecialFunctionHandler.h"

#include "klee/Config/config.h"
#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/KTest.h"
#include "klee/Internal/ADT/RNG.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/FloatEvaluation.h"
#include "klee/Internal/System/Time.h"
#include "klee/Interpreter.h"
#include "klee/TimerStatIncrementer.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprUtil.h"
#include "klee/util/GetElementPtrTypeIterator.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <vector>

#ifndef __MINGW32__
#include <sys/mman.h>
#endif

#include <cxxabi.h>
#include <errno.h>
#include <inttypes.h>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool> NoPreferCex("no-prefer-cex", cl::init(false));

cl::opt<bool> RandomizeFork("randomize-fork", cl::init(false));

cl::opt<bool> SimplifySymIndices("simplify-sym-indices", cl::init(true));

cl::opt<bool> SuppressExternalWarnings("suppress-external-warnings", cl::init(true));

cl::opt<bool> EmitAllErrors("emit-all-errors", cl::init(false),
                            cl::desc("Generate tests cases for all errors "
                                     "(default=one per (error,instruction) pair)"));

cl::opt<bool> NoExternals("no-externals", cl::desc("Do not allow external functin calls"));
} // namespace

namespace klee {
RNG theRNG;
extern cl::opt<bool> UseExprSimplifier;
} // namespace klee

Executor::Executor(InterpreterHandler *ih, LLVMContext &context)
    : kmodule(0), interpreterHandler(ih), searcher(0), externalDispatcher(new ExternalDispatcher()), statsTracker(0),
      specialFunctionHandler(0) {
}

const Module *Executor::setModule(llvm::Module *module, const ModuleOptions &opts, bool createStatsTracker) {
    assert(!kmodule && module && "can only register one module"); // XXX gross

    kmodule = new KModule(module);

    // Initialize the context.
    DataLayout *TD = kmodule->dataLayout;
    Context::initialize(TD->isLittleEndian(), (Expr::Width) TD->getPointerSizeInBits());

    specialFunctionHandler = new SpecialFunctionHandler(*this);

    specialFunctionHandler->prepare();

    if (opts.Snapshot) {
        kmodule->linkLibraries(opts);
        kmodule->buildShadowStructures();
    } else {
        kmodule->prepare(opts, interpreterHandler);
    }

    specialFunctionHandler->bind();

    if (createStatsTracker && StatsTracker::useStatistics()) {
        statsTracker = new StatsTracker(*this, interpreterHandler->getOutputFilename("assembly.ll"));
        statsTracker->writeHeaders();
    }

    return module;
}

Executor::~Executor() {
    delete externalDispatcher;
    if (specialFunctionHandler)
        delete specialFunctionHandler;
    if (statsTracker)
        delete statsTracker;
    delete kmodule;
}

/***/

void Executor::initializeGlobalObject(ExecutionState &state, const ObjectStatePtr &os, Constant *c, unsigned offset) {
    DataLayout *dataLayout = kmodule->dataLayout;
    if (ConstantVector *cp = dyn_cast<ConstantVector>(c)) {
        unsigned elementSize = dataLayout->getTypeStoreSize(cp->getType()->getElementType());
        for (unsigned i = 0, e = cp->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, cp->getOperand(i), offset + i * elementSize);
    } else if (isa<ConstantAggregateZero>(c)) {
        unsigned i, size = dataLayout->getTypeStoreSize(c->getType());
        for (i = 0; i < size; i++)
            os->write8(offset + i, (uint8_t) 0);
    } else if (ConstantArray *ca = dyn_cast<ConstantArray>(c)) {
        unsigned elementSize = dataLayout->getTypeStoreSize(ca->getType()->getElementType());
        for (unsigned i = 0, e = ca->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, ca->getOperand(i), offset + i * elementSize);
    } else if (ConstantDataArray *da = dyn_cast<ConstantDataArray>(c)) {
        unsigned elementSize = dataLayout->getTypeStoreSize(da->getType()->getElementType());
        for (unsigned i = 0, e = da->getNumElements(); i != e; ++i)
            initializeGlobalObject(state, os, da->getElementAsConstant(i), offset + i * elementSize);
    } else if (ConstantStruct *cs = dyn_cast<ConstantStruct>(c)) {
        const StructLayout *sl = dataLayout->getStructLayout(cast<StructType>(cs->getType()));
        for (unsigned i = 0, e = cs->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, cs->getOperand(i), offset + sl->getElementOffset(i));
    } else {
        unsigned StoreBits = dataLayout->getTypeStoreSizeInBits(c->getType());
        ref<ConstantExpr> C = evalConstant(c);

        // Extend the constant if necessary;
        assert(StoreBits >= C->getWidth() && "Invalid store size!");
        if (StoreBits > C->getWidth())
            C = C->ZExt(StoreBits);

        os->write(offset, C);
    }
}

ObjectStatePtr Executor::addExternalObject(ExecutionState &state, void *addr, unsigned size, bool isReadOnly,
                                           bool isSharedConcrete) {
    auto ret = ObjectState::allocate((uint64_t) addr, size, true);
    state.bindObject(ret, false);
    ret->setSharedConcrete(isSharedConcrete);
    if (!isSharedConcrete) {
        memcpy(ret->getConcreteBuffer(), addr, size);
    }

    ret->setReadOnly(isReadOnly);

    return ret;
}

void Executor::initializeGlobals(ExecutionState &state) {
    Module *m = kmodule->module;

    if (m->getModuleInlineAsm() != "")
        klee_warning("executable has module level assembly (ignoring)");

    // represent function globals using the address of the actual llvm function
    // object. given that we use malloc to allocate memory in states this also
    // ensures that we won't conflict. we don't need to allocate a memory object
    // since reading/writing via a function pointer is unsupported anyway.
    for (Module::iterator i = m->begin(), ie = m->end(); i != ie; ++i) {
        Function *f = &*i;
        ref<ConstantExpr> addr(0);

        // If the symbol has external weak linkage then it is implicitly
        // not defined in this module; if it isn't resolvable then it
        // should be null.
        if (f->hasExternalWeakLinkage() && !externalDispatcher->resolveSymbol(f->getName())) {
            addr = Expr::createPointer(0);
        } else {
            addr = Expr::createPointer((uintptr_t)(void *) f);
        }

        globalAddresses.insert(std::make_pair(f, addr));
    }

// Disabled, we don't want to promote use of live externals.
#ifdef HAVE_CTYPE_EXTERNALS
#ifndef WINDOWS
#ifndef DARWIN
    /* From /usr/include/errno.h: it [errno] is a per-thread variable. */
    int *errno_addr = __errno_location();
    addExternalObject(state, (void *) errno_addr, sizeof *errno_addr, false);

    /* from /usr/include/ctype.h:
         These point into arrays of 384, so they can be indexed by any `unsigned
         char' value [0,255]; by EOF (-1); or by any `signed char' value
         [-128,-1).  ISO C requires that the ctype functions work for `unsigned */
    const uint16_t **addr = __ctype_b_loc();
    addExternalObject(state, (void *) (*addr - 128), 384 * sizeof **addr, true);
    addExternalObject(state, addr, sizeof(*addr), true);

    const int32_t **lower_addr = __ctype_tolower_loc();
    addExternalObject(state, (void *) (*lower_addr - 128), 384 * sizeof **lower_addr, true);
    addExternalObject(state, lower_addr, sizeof(*lower_addr), true);

    const int32_t **upper_addr = __ctype_toupper_loc();
    addExternalObject(state, (void *) (*upper_addr - 128), 384 * sizeof **upper_addr, true);
    addExternalObject(state, upper_addr, sizeof(*upper_addr), true);
#endif
#endif
#endif

    // allocate and initialize globals, done in two passes since we may
    // need address of a global in order to initialize some other one.

    // allocate memory objects for all globals
    for (Module::const_global_iterator i = m->global_begin(), e = m->global_end(); i != e; ++i) {
        std::map<std::string, void *>::iterator po = predefinedSymbols.find(i->getName());
        if (po != predefinedSymbols.end()) {
            // This object was externally defined
            globalAddresses.insert(
                std::make_pair(&*i, ConstantExpr::create((uint64_t) po->second, sizeof(void *) * 8)));

        } else if (i->isDeclaration()) {
            // FIXME: We have no general way of handling unknown external
            // symbols. If we really cared about making external stuff work
            // better we could support user definition, or use the EXE style
            // hack where we check the object file information.

            Type *ty = i->getType()->getElementType();
            uint64_t size = kmodule->dataLayout->getTypeStoreSize(ty);

// XXX - DWD - hardcode some things until we decide how to fix.
#ifndef WINDOWS
            if (i->getName() == "_ZTVN10__cxxabiv117__class_type_infoE") {
                size = 0x2C;
            } else if (i->getName() == "_ZTVN10__cxxabiv120__si_class_type_infoE") {
                size = 0x2C;
            } else if (i->getName() == "_ZTVN10__cxxabiv121__vmi_class_type_infoE") {
                size = 0x2C;
            }
#endif

            if (size == 0) {
                llvm::errs() << "Unable to find size for global variable: " << i->getName()
                             << " (use will result in out of bounds access)\n";
            }

            auto mo = ObjectState::allocate(0, size, false);
            state.bindObject(mo, false);
            globalObjects.insert(std::make_pair(&*i, mo->getKey()));
            globalAddresses.insert(std::make_pair(&*i, mo->getBaseExpr()));

            // Program already running = object already initialized.  Read
            // concrete value and write it to our copy.
            if (size) {
                void *addr;
                addr = externalDispatcher->resolveSymbol(i->getName());

                if (!addr)
                    klee_error("unable to load symbol(%s) while initializing globals.", i->getName().data());

                for (unsigned offset = 0; offset < mo->getSize(); offset++) {
                    mo->write8(offset, ((unsigned char *) addr)[offset]);
                }
            }
        } else {
            Type *ty = i->getType()->getElementType();
            uint64_t size = kmodule->dataLayout->getTypeStoreSize(ty);
            auto mo = ObjectState::allocate(0, size, false);

            assert(mo && "out of memory");
            state.bindObject(mo, false);
            globalObjects.insert(std::make_pair(&*i, mo->getKey()));
            globalAddresses.insert(std::make_pair(&*i, mo->getBaseExpr()));
        }
    }

    // link aliases to their definitions (if bound)
    for (Module::alias_iterator i = m->alias_begin(), ie = m->alias_end(); i != ie; ++i) {
        // Map the alias to its aliasee's address. This works because we have
        // addresses for everything, even undefined functions.
        globalAddresses.insert(std::make_pair(&*i, evalConstant(i->getAliasee())));
    }

    // once all objects are allocated, do the actual initialization
    for (Module::global_iterator i = m->global_begin(), e = m->global_end(); i != e; ++i) {
        if (predefinedSymbols.find(i->getName()) != predefinedSymbols.end()) {
            continue;
        }

        if (i->hasInitializer()) {
            assert(globalObjects.find(&*i) != globalObjects.end());
            auto mo = globalObjects.find(&*i)->second;
            auto os = state.addressSpace.findObject(mo.address);
            assert(os);
            auto wos = state.addressSpace.getWriteable(os);
            initializeGlobalObject(state, wos, i->getInitializer(), 0);
            // if(i->isConstant()) os->setReadOnly(true);
        }
    }
}

void Executor::notifyBranch(ExecutionState &state) {
    // Should not get here
    pabort("Must go through S2E");
}

Executor::StatePair Executor::fork(ExecutionState &current, const ref<Expr> &condition_,
                                   bool keepConditionTrueInCurrentState) {
    auto condition = current.simplifyExpr(condition_);

    // If we are passed a constant, no need to do anything
    if (auto ce = dyn_cast<ConstantExpr>(condition)) {
        if (ce->isTrue()) {
            return StatePair(&current, 0);
        } else {
            return StatePair(0, &current);
        }
    }

    // Evaluate the expression using the current variable assignment
    ref<Expr> evalResult = current.concolics->evaluate(condition);
    ConstantExpr *ce = dyn_cast<ConstantExpr>(evalResult);
    check(ce, "Could not evaluate the expression to a constant.");
    bool conditionIsTrue = ce->isTrue();

    if (current.forkDisabled) {
        if (conditionIsTrue) {
            if (!current.addConstraint(condition)) {
                abort();
            }
            return StatePair(&current, 0);
        } else {
            if (!current.addConstraint(Expr::createIsZero(condition))) {
                abort();
            }
            return StatePair(0, &current);
        }
    }

    // Extract symbolic objects
    ArrayVec symbObjects = current.symbolics;

    if (keepConditionTrueInCurrentState && !conditionIsTrue) {
        // Recompute concrete values to keep condition true in current state

        // Build constraints where condition must be true
        ConstraintManager tmpConstraints = current.constraints();
        tmpConstraints.addConstraint(condition);

        std::vector<std::vector<unsigned char>> concreteObjects;
        auto solver = SolverManager::solver(current);
        if (!solver->getInitialValues(tmpConstraints, symbObjects, concreteObjects, current.queryCost)) {
            // Condition is always false in the current state
            return StatePair(0, &current);
        }

        // Update concrete values
        current.concolics->clear();
        for (unsigned i = 0; i < symbObjects.size(); ++i) {
            current.concolics->add(symbObjects[i], concreteObjects[i]);
        }

        conditionIsTrue = true;
    }

    // Build constraints for branched state
    ConstraintManager tmpConstraints = current.constraints();
    if (conditionIsTrue) {
        tmpConstraints.addConstraint(Expr::createIsZero(condition));
    } else {
        tmpConstraints.addConstraint(condition);
    }

    std::vector<std::vector<unsigned char>> concreteObjects;
    auto solver = SolverManager::solver(current);
    if (!solver->getInitialValues(tmpConstraints, symbObjects, concreteObjects, current.queryCost)) {
        if (conditionIsTrue) {
            return StatePair(&current, 0);
        } else {
            return StatePair(0, &current);
        }
    }

    // Branch
    ExecutionState *branchedState;
    notifyBranch(current);
    branchedState = current.branch();
    addedStates.insert(branchedState);

    // Update concrete values for the branched state
    branchedState->concolics->clear();
    for (unsigned i = 0; i < symbObjects.size(); ++i) {
        branchedState->concolics->add(symbObjects[i], concreteObjects[i]);
    }

    // Add constraint to both states
    if (conditionIsTrue) {
        if (!current.addConstraint(condition)) {
            abort();
        }
        if (!branchedState->addConstraint(Expr::createIsZero(condition))) {
            abort();
        }
    } else {
        if (!current.addConstraint(Expr::createIsZero(condition))) {
            abort();
        }
        if (!branchedState->addConstraint(condition)) {
            abort();
        }
    }

    // Classify states
    ExecutionState *trueState, *falseState;
    if (conditionIsTrue) {
        trueState = &current;
        falseState = branchedState;
    } else {
        falseState = &current;
        trueState = branchedState;
    }

    return StatePair(trueState, falseState);
}

void Executor::notifyFork(ExecutionState &originalState, ref<Expr> &condition, Executor::StatePair &targets) {
    // Should not get here
    pabort("Must go through S2E");
}

const Cell &Executor::eval(KInstruction *ki, unsigned index, ExecutionState &state) const {
    assert(index < ki->inst->getNumOperands());
    int vnumber = ki->operands[index];

    assert(vnumber != -1 && "Invalid operand to eval(), not a value or constant!");

    // Determine if this is a constant or not.
    if (vnumber < 0) {
        unsigned index = -vnumber - 2;
        return kmodule->constantTable[index];
    } else {
        unsigned index = vnumber;
        StackFrame &sf = state.stack.back();
        //*klee_warning_stream << "op idx=" << std::dec << index << '\n';
        return sf.locals[index];
    }
}

void Executor::executeCall(ExecutionState &state, KInstruction *ki, Function *f, std::vector<ref<Expr>> &arguments) {
    Instruction *i = ki->inst;

    if (f && overridenInternalFunctions.find(f) != overridenInternalFunctions.end()) {
        callExternalFunction(state, ki, f, arguments);
    } else

        if (f && f->isDeclaration()) {
        switch (f->getIntrinsicID()) {
            case Intrinsic::not_intrinsic:
                // state may be destroyed by this call, cannot touch
                callExternalFunction(state, ki, f, arguments);
                break;

            // va_arg is handled by caller and intrinsic lowering, see comment for
            // ExecutionState::varargs
            case Intrinsic::vastart: {
                StackFrame &sf = state.stack.back();
                assert(sf.varargs.size() && "vastart called in function with no vararg object");

                // FIXME: This is really specific to the architecture, not the pointer
                // size. This happens to work fir x86-32 and x86-64, however.
                Expr::Width WordSize = Context::get().getPointerWidth();
                if (WordSize == Expr::Int32) {
                    executeMemoryOperation(state, true, arguments[0], sf.varargs[0].getBaseExpr(), 0);
                } else {
                    assert(WordSize == Expr::Int64 && "Unknown word size!");

                    // X86-64 has quite complicated calling convention. However,
                    // instead of implementing it, we can do a simple hack: just
                    // make a function believe that all varargs are on stack.
                    executeMemoryOperation(state, true, arguments[0], ConstantExpr::create(48, 32), 0); // gp_offset
                    executeMemoryOperation(state, true, AddExpr::create(arguments[0], ConstantExpr::create(4, 64)),
                                           ConstantExpr::create(304, 32), 0); // fp_offset
                    executeMemoryOperation(state, true, AddExpr::create(arguments[0], ConstantExpr::create(8, 64)),
                                           sf.varargs[0].getBaseExpr(), 0); // overflow_arg_area
                    executeMemoryOperation(state, true, AddExpr::create(arguments[0], ConstantExpr::create(16, 64)),
                                           ConstantExpr::create(0, 64), 0); // reg_save_area
                }
                break;
            }
            case Intrinsic::vaend:
                // va_end is a noop for the interpreter.
                //
                // FIXME: We should validate that the target didn't do something bad
                // with vaeend, however (like call it twice).
                break;

            case Intrinsic::vacopy:
            // va_copy should have been lowered.
            //
            // FIXME: It would be nice to check for errors in the usage of this as
            // well.
            default:
                klee_error("unknown intrinsic: %s", f->getName().data());
        }

        if (InvokeInst *ii = dyn_cast<InvokeInst>(i))
            transferToBasicBlock(ii->getNormalDest(), i->getParent(), state);
    } else {
        // FIXME: I'm not really happy about this reliance on prevPC but it is ok, I
        // guess. This just done to avoid having to pass KInstIterator everywhere
        // instead of the actual instruction, since we can't make a KInstIterator
        // from just an instruction (unlike LLVM).
        KFunction *kf = kmodule->functionMap[f];
        state.pushFrame(state.prevPC, kf);
        state.pc = kf->instructions;

        // TODO: support "byval" parameter attribute
        // TODO: support zeroext, signext, sret attributes

        unsigned callingArgs = arguments.size();
        unsigned funcArgs = f->arg_size();
        if (!f->isVarArg()) {
            if (callingArgs > funcArgs) {
                klee_warning_once(f, "calling %s with extra arguments.", f->getName().data());
            } else if (callingArgs < funcArgs) {
                terminateState(state, "calling function with too few arguments");
                return;
            }
        } else {
            if (callingArgs < funcArgs) {
                terminateState(state, "calling function with too few arguments");
                return;
            }

            StackFrame &sf = state.stack.back();
            unsigned size = 0;
            for (unsigned i = funcArgs; i < callingArgs; i++) {
                // FIXME: This is really specific to the architecture, not the pointer
                // size. This happens to work fir x86-32 and x86-64, however.
                Expr::Width WordSize = Context::get().getPointerWidth();
                if (WordSize == Expr::Int32) {
                    size += Expr::getMinBytesForWidth(arguments[i]->getWidth());
                } else {
                    size += llvm::alignTo(arguments[i]->getWidth(), WordSize) / 8;
                }
            }

            auto mo = ObjectState::allocate(0, size, false);
            if (!mo) {
                terminateState(state, "out of memory (varargs)");
                return;
            }

            sf.varargs.push_back(mo->getKey());

            state.bindObject(mo, true);
            unsigned offset = 0;
            for (unsigned i = funcArgs; i < callingArgs; i++) {
                // FIXME: This is really specific to the architecture, not the pointer
                // size. This happens to work fir x86-32 and x86-64, however.
                Expr::Width WordSize = Context::get().getPointerWidth();
                if (WordSize == Expr::Int32) {
                    mo->write(offset, arguments[i]);
                    offset += Expr::getMinBytesForWidth(arguments[i]->getWidth());
                } else {
                    assert(WordSize == Expr::Int64 && "Unknown word size!");
                    mo->write(offset, arguments[i]);
                    offset += llvm::alignTo(arguments[i]->getWidth(), WordSize) / 8;
                }
            }
        }

        unsigned numFormals = f->arg_size();
        for (unsigned i = 0; i < numFormals; ++i) {
            state.bindArgument(kf, i, arguments[i]);
        }
    }
}

void Executor::transferToBasicBlock(BasicBlock *dst, BasicBlock *src, ExecutionState &state) {
    // Note that in general phi nodes can reuse phi values from the same
    // block but the incoming value is the eval() result *before* the
    // execution of any phi nodes. this is pathological and doesn't
    // really seem to occur, but just in case we run the PhiCleanerPass
    // which makes sure this cannot happen and so it is safe to just
    // eval things in order. The PhiCleanerPass also makes sure that all
    // incoming blocks have the same order for each PHINode so we only
    // have to compute the index once.
    //
    // With that done we simply set an index in the state so that PHI
    // instructions know which argument to eval, set the pc, and continue.

    // XXX this lookup has to go ?
    KFunction *kf = state.stack.back().kf;
    unsigned entry = kf->basicBlockEntry[dst];
    state.pc = &kf->instructions[entry];
    if (state.pc->inst->getOpcode() == Instruction::PHI) {
        PHINode *first = static_cast<PHINode *>(state.pc->inst);
        state.incomingBBIndex = first->getBasicBlockIndex(src);
    }
}

Function *Executor::getCalledFunction(CallSite &cs, ExecutionState &state) {
    Function *f = cs.getCalledFunction();

    if (f) {
        std::string alias = state.getFnAlias(f->getName());
        if (alias != "") {
            llvm::Module *currModule = kmodule->module;
            Function *old_f = f;
            f = currModule->getFunction(alias);
            if (!f) {
                llvm::errs() << "Function " << alias << "(), alias for " << old_f->getName() << " not found!\n";
                assert(f && "function alias not found");
            }
        }
    }

    return f;
}

static inline const llvm::fltSemantics *fpWidthToSemantics(unsigned width) {
    switch (width) {
        case Expr::Int32:
            return &llvm::APFloat::IEEEsingle();
        case Expr::Int64:
            return &llvm::APFloat::IEEEdouble();
        default:
            return 0;
    }
}

void Executor::executeInstruction(ExecutionState &state, KInstruction *ki) {
    Instruction *i = ki->inst;
    switch (i->getOpcode()) {
        // Control flow
        case Instruction::Ret: {
            ReturnInst *ri = cast<ReturnInst>(i);
            KInstIterator kcaller = state.stack.back().caller;
            Instruction *caller = kcaller ? kcaller->inst : 0;
            bool isVoidReturn = (ri->getNumOperands() == 0);
            ref<Expr> result = ConstantExpr::alloc(0, Expr::Bool);

            if (!isVoidReturn) {
                result = eval(ki, 0, state).value;
            }

            if (state.stack.size() <= 1) {
                assert(!caller && "caller set on initial stack frame");
                terminateState(state);
            } else {
                state.popFrame();

                if (InvokeInst *ii = dyn_cast<InvokeInst>(caller)) {
                    transferToBasicBlock(ii->getNormalDest(), caller->getParent(), state);
                } else {
                    state.pc = kcaller;
                    ++state.pc;
                }

                if (!isVoidReturn) {
                    Type *t = caller->getType();
                    if (t != Type::getVoidTy(caller->getContext())) {
                        // may need to do coercion due to bitcasts
                        Expr::Width from = result->getWidth();
                        Expr::Width to = getWidthForLLVMType(t);

                        if (from != to) {
                            CallSite cs = (isa<InvokeInst>(caller) ? CallSite(cast<InvokeInst>(caller))
                                                                   : CallSite(cast<CallInst>(caller)));

                            // XXX need to check other param attrs ?
                            if (cs.paramHasAttr(0, llvm::Attribute::SExt)) {
                                result = SExtExpr::create(result, to);
                            } else {
                                result = ZExtExpr::create(result, to);
                            }
                        }

                        state.bindLocal(kcaller, result);
                    }
                } else {
                    // We check that the return value has no users instead of
                    // checking the type, since C defaults to returning int for
                    // undeclared functions.
                    if (!caller->use_empty()) {
                        terminateState(state, "return void when caller expected a result");
                    }
                }
            }
            break;
        }
        case Instruction::Br: {
            BranchInst *bi = cast<BranchInst>(i);
            if (bi->isUnconditional()) {
                transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), state);
            } else {
                // FIXME: Find a way that we don't have this hidden dependency.
                assert(bi->getCondition() == bi->getOperand(0) && "Wrong operand index!");
                ref<Expr> cond = eval(ki, 0, state).value;
                Executor::StatePair branches = fork(state, cond);

                if (branches.first)
                    transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), *branches.first);
                if (branches.second)
                    transferToBasicBlock(bi->getSuccessor(1), bi->getParent(), *branches.second);

                notifyFork(state, cond, branches);
            }
            break;
        }
        case Instruction::Switch: {
            SwitchInst *si = cast<SwitchInst>(i);
            ref<Expr> cond = eval(ki, 0, state).value;

            cond = state.simplifyExpr(state.toUnique(cond));

            klee::ref<klee::Expr> concreteCond = state.concolics->evaluate(cond);
            klee::ref<klee::Expr> condition = EqExpr::create(concreteCond, cond);
            StatePair sp = fork(state, condition);
            assert(sp.first == &state);
            if (sp.second) {
                sp.second->pc = sp.second->prevPC;
            }
            notifyFork(state, cond, sp);
            cond = concreteCond;

            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(cond)) {
                // Somewhat gross to create these all the time, but fine till we
                // switch to an internal rep.
                llvm::IntegerType *Ty = cast<IntegerType>(si->getCondition()->getType());
                ConstantInt *ci = ConstantInt::get(Ty, CE->getZExtValue());
                SwitchInst::CaseIt cit = si->findCaseValue(ci);
                transferToBasicBlock(cit->getCaseSuccessor(), si->getParent(), state);
            } else {
                pabort("Cannot get here in concolic mode");
                abort();
            }
            break;
        }
        case Instruction::Unreachable:
            // Note that this is not necessarily an internal bug, llvm will
            // generate unreachable instructions in cases where it knows the
            // program will crash. So it is effectively a SEGV or internal
            // error.
            terminateState(state, "reached \"unreachable\" instruction");
            break;

        case Instruction::Invoke:
        case Instruction::Call: {
            CallSite cs;
            unsigned argStart;
            if (i->getOpcode() == Instruction::Call) {
                cs = CallSite(cast<CallInst>(i));
                argStart = 1;
            } else {
                cs = CallSite(cast<InvokeInst>(i));
                argStart = 3;
            }

            unsigned numArgs = cs.arg_size();
            Function *f = getCalledFunction(cs, state);

            // evaluate arguments
            std::vector<ref<Expr>> arguments;
            arguments.reserve(numArgs);

            for (unsigned j = 0; j < numArgs; ++j)
                arguments.push_back(eval(ki, argStart + j, state).value);

            if (!f) {
                // special case the call with a bitcast case
                Value *fp = cs.getCalledValue();
                llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(fp);

                if (ce && ce->getOpcode() == Instruction::BitCast) {
                    f = dyn_cast<Function>(ce->getOperand(0));
                    assert(f && "XXX unrecognized constant expression in call");
                    const FunctionType *fType =
                        dyn_cast<FunctionType>(cast<PointerType>(f->getType())->getElementType());
                    const FunctionType *ceType =
                        dyn_cast<FunctionType>(cast<PointerType>(ce->getType())->getElementType());
                    check(fType && ceType, "unable to get function type");

                    // XXX check result coercion

                    // XXX this really needs thought and validation
                    unsigned i = 0;
                    for (std::vector<ref<Expr>>::iterator ai = arguments.begin(), ie = arguments.end(); ai != ie;
                         ++ai) {
                        Expr::Width to, from = (*ai)->getWidth();

                        if (i < fType->getNumParams()) {
                            to = getWidthForLLVMType(fType->getParamType(i));

                            if (from != to) {
                                // XXX need to check other param attrs ?
                                if (cs.paramHasAttr(i + 1, llvm::Attribute::SExt)) {
                                    arguments[i] = SExtExpr::create(arguments[i], to);
                                } else {
                                    arguments[i] = ZExtExpr::create(arguments[i], to);
                                }
                            }
                        }

                        i++;
                    }
                } else if (isa<InlineAsm>(fp)) {
                    terminateState(state, "inline assembly is unsupported");
                    break;
                }
            }

            if (f) {
                executeCall(state, ki, f, arguments);
            } else {
                ref<Expr> v = eval(ki, 0, state).value;
                ref<ConstantExpr> constantTarget = dyn_cast<ConstantExpr>(v);
                if (constantTarget.isNull()) {
                    terminateState(state, "the engine encountered a symbolic function pointer");
                    abort();
                }

                uint64_t addr = constantTarget->getZExtValue();
                CallInst *ci = dyn_cast<CallInst>(i);
                if (!ci) {
                    terminateState(state, "could not cast call inst");
                    abort();
                }

                Module *m = i->getParent()->getParent()->getParent();
                std::stringstream ss;
                ss << "ext_" << std::hex << addr;
                auto fcn = m->getOrInsertFunction(ss.str(), ci->getFunctionType());
                f = dyn_cast<Function>(fcn.getCallee());
                assert(f);

                // XXX: this is a hack caused by how klee handles external functions.
                // TODO: don't require registering external functions
                llvm::sys::DynamicLibrary::AddSymbol(ss.str(), (void *) addr);

                executeCall(state, ki, f, arguments);
            }
            break;
        }
        case Instruction::PHI: {
            ref<Expr> result = eval(ki, state.incomingBBIndex, state).value;
            state.bindLocal(ki, result);
            break;
        }

        // Special instructions
        case Instruction::Select: {
            SelectInst *SI = cast<SelectInst>(ki->inst);
            check(SI->getCondition() == SI->getOperand(0), "Wrong operand index!");
            ref<Expr> cond = eval(ki, 0, state).value;
            ref<Expr> tExpr = eval(ki, 1, state).value;
            ref<Expr> fExpr = eval(ki, 2, state).value;
            ref<Expr> result = SelectExpr::create(cond, tExpr, fExpr);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::VAArg:
            terminateState(state, "unexpected VAArg instruction");
            break;

            // Arithmetic / logical

        case Instruction::Add: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            state.bindLocal(ki, AddExpr::create(left, right));
            break;
        }

        case Instruction::Sub: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            state.bindLocal(ki, SubExpr::create(left, right));
            break;
        }

        case Instruction::Mul: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            state.bindLocal(ki, MulExpr::create(left, right));
            break;
        }

        case Instruction::UDiv: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = UDivExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::SDiv: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = SDivExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::URem: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = URemExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::SRem: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = SRemExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::And: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = AndExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::Or: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = OrExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::Xor: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = XorExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::Shl: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = ShlExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::LShr: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = LShrExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::AShr: {
            ref<Expr> left = eval(ki, 0, state).value;
            ref<Expr> right = eval(ki, 1, state).value;
            ref<Expr> result = AShrExpr::create(left, right);
            state.bindLocal(ki, result);
            break;
        }

            // Compare

        case Instruction::ICmp: {
            CmpInst *ci = cast<CmpInst>(i);
            ICmpInst *ii = cast<ICmpInst>(ci);

            switch (ii->getPredicate()) {
                case ICmpInst::ICMP_EQ: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = EqExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_NE: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = NeExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_UGT: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = UgtExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_UGE: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = UgeExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_ULT: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = UltExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_ULE: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = UleExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_SGT: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = SgtExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_SGE: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = SgeExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_SLT: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = SltExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                case ICmpInst::ICMP_SLE: {
                    ref<Expr> left = eval(ki, 0, state).value;
                    ref<Expr> right = eval(ki, 1, state).value;
                    ref<Expr> result = SleExpr::create(left, right);
                    state.bindLocal(ki, result);
                    break;
                }

                default:
                    terminateState(state, "invalid ICmp predicate");
            }
            break;
        }

// Memory instructions...
#if (LLVM_VERSION_MAJOR == 2 && LLVM_VERSION_MINOR < 7)
        case Instruction::Malloc:
        case Instruction::Alloca: {
            AllocationInst *ai = cast<AllocationInst>(i);
#else
        case Instruction::Alloca: {
            AllocaInst *ai = cast<AllocaInst>(i);
#endif
            unsigned elementSize = kmodule->dataLayout->getTypeStoreSize(ai->getAllocatedType());
            ref<Expr> size = Expr::createPointer(elementSize);
            if (ai->isArrayAllocation()) {
                ref<Expr> count = eval(ki, 0, state).value;
                count = Expr::createCoerceToPointerType(count);
                size = MulExpr::create(size, count);
            }
            bool isLocal = i->getOpcode() == Instruction::Alloca;
            executeAlloc(state, size, isLocal, ki);
            break;
        }

        case Instruction::Load: {
            ref<Expr> base = eval(ki, 0, state).value;
            executeMemoryOperation(state, false, base, 0, ki);
            break;
        }
        case Instruction::Store: {
            ref<Expr> base = eval(ki, 1, state).value;
            ref<Expr> value = eval(ki, 0, state).value;
            executeMemoryOperation(state, true, base, value, 0);
            break;
        }

        case Instruction::GetElementPtr: {
            KGEPInstruction *kgepi = static_cast<KGEPInstruction *>(ki);
            ref<Expr> base = eval(ki, 0, state).value;

            for (std::vector<std::pair<unsigned, uint64_t>>::iterator it = kgepi->indices.begin(),
                                                                      ie = kgepi->indices.end();
                 it != ie; ++it) {
                uint64_t elementSize = it->second;
                ref<Expr> index = eval(ki, it->first, state).value;
                base = AddExpr::create(
                    base, MulExpr::create(Expr::createCoerceToPointerType(index), Expr::createPointer(elementSize)));
            }
            if (kgepi->offset)
                base = AddExpr::create(base, Expr::createPointer(kgepi->offset));
            state.bindLocal(ki, base);
            break;
        }

        // Conversion
        case Instruction::Trunc: {
            CastInst *ci = cast<CastInst>(i);
            ref<Expr> result = ExtractExpr::create(eval(ki, 0, state).value, 0, getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }
        case Instruction::ZExt: {
            CastInst *ci = cast<CastInst>(i);
            ref<Expr> result = ZExtExpr::create(eval(ki, 0, state).value, getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }
        case Instruction::SExt: {
            CastInst *ci = cast<CastInst>(i);
            ref<Expr> result = SExtExpr::create(eval(ki, 0, state).value, getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::IntToPtr: {
            CastInst *ci = cast<CastInst>(i);
            Expr::Width pType = getWidthForLLVMType(ci->getType());
            ref<Expr> arg = eval(ki, 0, state).value;
            state.bindLocal(ki, ZExtExpr::create(arg, pType));
            break;
        }
        case Instruction::PtrToInt: {
            CastInst *ci = cast<CastInst>(i);
            Expr::Width iType = getWidthForLLVMType(ci->getType());
            ref<Expr> arg = eval(ki, 0, state).value;
            state.bindLocal(ki, ZExtExpr::create(arg, iType));
            break;
        }

        case Instruction::BitCast: {
            ref<Expr> result = eval(ki, 0, state).value;
            state.bindLocal(ki, result);
            break;
        }

            // Floating point instructions

        case Instruction::FAdd: {
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            Res.add(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()), APFloat::rmNearestTiesToEven);
            state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
            break;
        }

        case Instruction::FSub: {
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            Res.subtract(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()),
                         APFloat::rmNearestTiesToEven);
            state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
            break;
        }

        case Instruction::FMul: {
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            Res.multiply(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()),
                         APFloat::rmNearestTiesToEven);
            state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
            break;
        }

        case Instruction::FDiv: {
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            Res.divide(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()),
                       APFloat::rmNearestTiesToEven);
            state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
            break;
        }

        case Instruction::FRem: {
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            Res.mod(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()));
            state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
            break;
        }

        case Instruction::FPTrunc: {
            FPTruncInst *fi = cast<FPTruncInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPTrunc operation");
            uint64_t value = floats::trunc(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPExt: {
            FPExtInst *fi = cast<FPExtInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPExt operation");
            uint64_t value = floats::ext(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPToUI: {
            FPToUIInst *fi = cast<FPToUIInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPToUI operation");
            uint64_t value = floats::toUnsignedInt(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPToSI: {
            FPToSIInst *fi = cast<FPToSIInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPToSI operation");
            uint64_t value = floats::toSignedInt(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::UIToFP: {
            UIToFPInst *fi = cast<UIToFPInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported UIToFP operation");
            uint64_t value = floats::UnsignedIntToFP(arg->getZExtValue(), resultType);
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::SIToFP: {
            SIToFPInst *fi = cast<SIToFPInst>(i);
            Expr::Width resultType = getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported SIToFP operation");
            uint64_t value = floats::SignedIntToFP(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FCmp: {
            FCmpInst *fi = cast<FCmpInst>(i);
            ref<ConstantExpr> left = state.toConstant(eval(ki, 0, state).value, "floating point");
            ref<ConstantExpr> right = state.toConstant(eval(ki, 1, state).value, "floating point");
            APFloat LHS(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
            APFloat RHS(*fpWidthToSemantics(right->getWidth()), right->getAPValue());
            APFloat::cmpResult CmpRes = LHS.compare(RHS);

            bool Result = false;
            switch (fi->getPredicate()) {
                // Predicates which only care about whether or not the operands are NaNs.
                case FCmpInst::FCMP_ORD:
                    Result = CmpRes != APFloat::cmpUnordered;
                    break;

                case FCmpInst::FCMP_UNO:
                    Result = CmpRes == APFloat::cmpUnordered;
                    break;

                // Ordered comparisons return false if either operand is NaN.  Unordered
                // comparisons return true if either operand is NaN.
                case FCmpInst::FCMP_UEQ:
                    if (CmpRes == APFloat::cmpUnordered) {
                        Result = true;
                        break;
                    }
                case FCmpInst::FCMP_OEQ:
                    Result = CmpRes == APFloat::cmpEqual;
                    break;

                case FCmpInst::FCMP_UGT:
                    if (CmpRes == APFloat::cmpUnordered) {
                        Result = true;
                        break;
                    }
                case FCmpInst::FCMP_OGT:
                    Result = CmpRes == APFloat::cmpGreaterThan;
                    break;

                case FCmpInst::FCMP_UGE:
                    if (CmpRes == APFloat::cmpUnordered) {
                        Result = true;
                        break;
                    }
                case FCmpInst::FCMP_OGE:
                    Result = CmpRes == APFloat::cmpGreaterThan || CmpRes == APFloat::cmpEqual;
                    break;

                case FCmpInst::FCMP_ULT:
                    if (CmpRes == APFloat::cmpUnordered) {
                        Result = true;
                        break;
                    }
                case FCmpInst::FCMP_OLT:
                    Result = CmpRes == APFloat::cmpLessThan;
                    break;

                case FCmpInst::FCMP_ULE:
                    if (CmpRes == APFloat::cmpUnordered) {
                        Result = true;
                        break;
                    }
                case FCmpInst::FCMP_OLE:
                    Result = CmpRes == APFloat::cmpLessThan || CmpRes == APFloat::cmpEqual;
                    break;

                case FCmpInst::FCMP_UNE:
                    Result = CmpRes == APFloat::cmpUnordered || CmpRes != APFloat::cmpEqual;
                    break;
                case FCmpInst::FCMP_ONE:
                    Result = CmpRes != APFloat::cmpUnordered && CmpRes != APFloat::cmpEqual;
                    break;

                default:
                    pabort("Invalid FCMP predicate!");
                case FCmpInst::FCMP_FALSE:
                    Result = false;
                    break;
                case FCmpInst::FCMP_TRUE:
                    Result = true;
                    break;
            }

            state.bindLocal(ki, ConstantExpr::alloc(Result, Expr::Bool));
            break;
        }

        case Instruction::InsertValue: {
            KGEPInstruction *kgepi = static_cast<KGEPInstruction *>(ki);

            ref<Expr> agg = eval(ki, 0, state).value;
            ref<Expr> val = eval(ki, 1, state).value;

            ref<Expr> l = NULL, r = NULL;
            unsigned lOffset = kgepi->offset * 8, rOffset = kgepi->offset * 8 + val->getWidth();

            if (lOffset > 0)
                l = ExtractExpr::create(agg, 0, lOffset);
            if (rOffset < agg->getWidth())
                r = ExtractExpr::create(agg, rOffset, agg->getWidth() - rOffset);

            ref<Expr> result;
            if (!l.isNull() && !r.isNull())
                result = ConcatExpr::create(r, ConcatExpr::create(val, l));
            else if (!l.isNull())
                result = ConcatExpr::create(val, l);
            else if (!r.isNull())
                result = ConcatExpr::create(r, val);
            else
                result = val;

            state.bindLocal(ki, result);
            break;
        }
        case Instruction::ExtractValue: {
            KGEPInstruction *kgepi = static_cast<KGEPInstruction *>(ki);

            ref<Expr> agg = eval(ki, 0, state).value;

            ref<Expr> result = ExtractExpr::create(agg, kgepi->offset * 8, getWidthForLLVMType(i->getType()));

            state.bindLocal(ki, result);
            break;
        }

        case Instruction::InsertElement: {
            InsertElementInst *iei = cast<InsertElementInst>(i);
            ref<Expr> vec = eval(ki, 0, state).value;
            ref<Expr> newElt = eval(ki, 1, state).value;
            ref<Expr> idx = eval(ki, 2, state).value;

            ConstantExpr *cIdx = dyn_cast<ConstantExpr>(idx);
            if (cIdx == NULL) {
                terminateState(state, "InsertElement, support for symbolic index not implemented");
                return;
            }
            uint64_t iIdx = cIdx->getZExtValue();
            const llvm::VectorType *vt = iei->getType();
            unsigned EltBits = getWidthForLLVMType(vt->getElementType());

            if (iIdx >= vt->getNumElements()) {
                // Out of bounds write
                terminateState(state, "Out of bounds write when inserting element");
                return;
            }

            const unsigned elementCount = vt->getNumElements();
            llvm::SmallVector<ref<Expr>, 8> elems;
            elems.reserve(elementCount);
            for (unsigned i = elementCount; i != 0; --i) {
                auto of = i - 1;
                unsigned bitOffset = EltBits * of;
                elems.push_back(of == iIdx ? newElt : ExtractExpr::create(vec, bitOffset, EltBits));
            }

            assert(Context::get().isLittleEndian() && "FIXME:Broken for big endian");
            ref<Expr> Result = ConcatExpr::createN(elementCount, elems.data());
            state.bindLocal(ki, Result);
            break;
        }
        case Instruction::ExtractElement: {
            ExtractElementInst *eei = cast<ExtractElementInst>(i);
            ref<Expr> vec = eval(ki, 0, state).value;
            ref<Expr> idx = eval(ki, 1, state).value;

            ConstantExpr *cIdx = dyn_cast<ConstantExpr>(idx);
            if (cIdx == NULL) {
                terminateState(state, "ExtractElement, support for symbolic index not implemented");
                return;
            }
            uint64_t iIdx = cIdx->getZExtValue();
            const llvm::VectorType *vt = eei->getVectorOperandType();
            unsigned EltBits = getWidthForLLVMType(vt->getElementType());

            if (iIdx >= vt->getNumElements()) {
                // Out of bounds read
                terminateState(state, "Out of bounds read when extracting element");
                return;
            }

            unsigned bitOffset = EltBits * iIdx;
            ref<Expr> Result = ExtractExpr::create(vec, bitOffset, EltBits);
            state.bindLocal(ki, Result);
            break;
        }
        case Instruction::ShuffleVector:
            // Should never happen due to Scalarizer pass removing ShuffleVector
            // instructions.
            terminateState(state, "Unexpected ShuffleVector instruction");
            break;

        // Other instructions...
        // Unhandled
        default: {
            std::string errstr;
            llvm::raw_string_ostream err(errstr);
            err << *i;
            terminateState(state, "illegal instruction " + errstr);
        }

        break;
    }
}

void Executor::updateStates(ExecutionState *current) {
    if (searcher) {
        searcher->update(current, addedStates, removedStates);
    }

    states.insert(addedStates.begin(), addedStates.end());
    addedStates.clear();

    for (StateSet::iterator it = removedStates.begin(), ie = removedStates.end(); it != ie; ++it) {
        ExecutionState *es = *it;
        StateSet::iterator it2 = states.find(es);
        assert(it2 != states.end());
        states.erase(it2);
        deleteState(es);
    }
    removedStates.clear();
}

template <typename TypeIt> void Executor::computeOffsets(KGEPInstruction *kgepi, TypeIt ib, TypeIt ie) {
    auto &dataLayout = kmodule->module->getDataLayout();

    ref<ConstantExpr> constantOffset = ConstantExpr::alloc(0, Context::get().getPointerWidth());
    uint64_t index = 1;
    for (TypeIt ii = ib; ii != ie; ++ii) {
        if (StructType *st = dyn_cast<StructType>(*ii)) {
            const StructLayout *sl = dataLayout.getStructLayout(st);
            const ConstantInt *ci = cast<ConstantInt>(ii.getOperand());
            uint64_t addend = sl->getElementOffset((unsigned) ci->getZExtValue());
            constantOffset = constantOffset->Add(ConstantExpr::alloc(addend, Context::get().getPointerWidth()));
        } else if (const auto set = dyn_cast<SequentialType>(*ii)) {
            uint64_t elementSize = dataLayout.getTypeStoreSize(set->getElementType());
            Value *operand = ii.getOperand();
            if (Constant *c = dyn_cast<Constant>(operand)) {
                ref<ConstantExpr> index = evalConstant(c)->SExt(Context::get().getPointerWidth());
                ref<ConstantExpr> addend =
                    index->Mul(ConstantExpr::alloc(elementSize, Context::get().getPointerWidth()));
                constantOffset = constantOffset->Add(addend);
            } else {
                kgepi->indices.push_back(std::make_pair(index, elementSize));
            }
        } else if (const auto ptr = dyn_cast<PointerType>(*ii)) {
            auto elementSize = dataLayout.getTypeStoreSize(ptr->getElementType());
            auto operand = ii.getOperand();
            if (auto c = dyn_cast<Constant>(operand)) {
                auto index = evalConstant(c)->SExt(Context::get().getPointerWidth());
                auto addend = index->Mul(ConstantExpr::alloc(elementSize, Context::get().getPointerWidth()));
                constantOffset = constantOffset->Add(addend);
            } else {
                kgepi->indices.push_back(std::make_pair(index, elementSize));
            }
        } else
            assert("invalid type" && 0);
        index++;
    }
    kgepi->offset = constantOffset->getZExtValue();
}

void Executor::bindInstructionConstants(KInstruction *KI) {
    KGEPInstruction *kgepi = static_cast<KGEPInstruction *>(KI);

    if (GetElementPtrInst *gepi = dyn_cast<GetElementPtrInst>(KI->inst)) {
        computeOffsets(kgepi, klee::gep_type_begin(gepi), klee::gep_type_end(gepi));
    } else if (InsertValueInst *ivi = dyn_cast<InsertValueInst>(KI->inst)) {
        computeOffsets(kgepi, iv_type_begin(ivi), iv_type_end(ivi));
        assert(kgepi->indices.empty() && "InsertValue constant offset expected");
    } else if (ExtractValueInst *evi = dyn_cast<ExtractValueInst>(KI->inst)) {
        computeOffsets(kgepi, ev_type_begin(evi), ev_type_end(evi));
        assert(kgepi->indices.empty() && "ExtractValue constant offset expected");
    }
}

void Executor::bindModuleConstants() {
    for (std::vector<KFunction *>::iterator it = kmodule->functions.begin(), ie = kmodule->functions.end(); it != ie;
         ++it) {
        KFunction *kf = *it;
        for (unsigned i = 0; i < kf->numInstructions; ++i)
            bindInstructionConstants(kf->instructions[i]);
    }

    kmodule->constantTable.resize(kmodule->constants.size());
    for (unsigned i = 0; i < kmodule->constants.size(); ++i) {
        Cell &c = kmodule->constantTable[i];
        c.value = evalConstant(kmodule->constants[i]);
    }
}

void Executor::deleteState(ExecutionState *state) {
    SolverManager::get().removeState(state);

    delete state;
}

void Executor::terminateState(ExecutionState &state) {
    StateSet::iterator it = addedStates.find(&state);
    if (it == addedStates.end()) {
        // XXX: the following line makes delayed state termination impossible
        // state.pc = state.prevPC;

        removedStates.insert(&state);
    } else {
        // never reached searcher, just delete immediately
        addedStates.erase(it);
        deleteState(&state);
    }
}

void Executor::terminateState(ExecutionState &state, const std::string &reason) {
    *klee_warning_stream << "Terminating state: " << reason << "\n";
    terminateState(state);
}

// XXX shoot me
static const char *okExternalsList[] = {"printf", "fprintf", "puts", "getpid"};
static std::set<std::string> okExternals(okExternalsList,
                                         okExternalsList + (sizeof(okExternalsList) / sizeof(okExternalsList[0])));

extern "C" {
typedef uint64_t (*external_fcn_t)(...);
}

void Executor::callExternalFunction(ExecutionState &state, KInstruction *target, Function *function,
                                    std::vector<ref<Expr>> &arguments) {
    // check if specialFunctionHandler wants it
    if (specialFunctionHandler->handle(state, function, target, arguments))
        return;

    if (NoExternals && !okExternals.count(function->getName())) {
        llvm::errs() << "KLEE:ERROR: Calling not-OK external function : " << function->getName() << "\n";
        terminateState(state, "externals disallowed");
        return;
    }

    ExternalDispatcher::Arguments cas;

    unsigned i = 1;
    for (std::vector<ref<Expr>>::iterator ai = arguments.begin(), ae = arguments.end(); ai != ae; ++ai, ++i) {
        ref<Expr> arg = state.toUnique(*ai);
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(arg)) {
            // XXX kick toMemory functions from here
            cas.push_back(CE->getZExtValue());
        } else {
            // Fork all possible concrete solutions
            klee::ref<klee::ConstantExpr> concreteArg;
            klee::ref<klee::Expr> ca = state.concolics->evaluate(arg);
            assert(dyn_cast<klee::ConstantExpr>(ca) && "Could not evaluate address");
            concreteArg = dyn_cast<klee::ConstantExpr>(ca);

            klee::ref<klee::Expr> condition = EqExpr::create(concreteArg, arg);

            StatePair sp = fork(state, condition);

            assert(sp.first == &state);

            if (sp.second) {
                sp.second->pc = sp.second->prevPC;
            }

            KInstIterator savedPc = sp.first->pc;
            sp.first->pc = sp.first->prevPC;

            // This might throw an exception
            notifyFork(state, condition, sp);

            sp.first->pc = savedPc;

            cas.push_back(concreteArg->getZExtValue());
        }
    }

    if (!SuppressExternalWarnings) {
        std::ostringstream os;
        os << "calling external: " << function->getName().str() << "(";
        for (unsigned i = 0; i < arguments.size(); i++) {
            os << std::hex << arguments[i];
            if (i != arguments.size() - 1)
                os << ", ";
        }
        os << ")" << std::dec;

        klee_warning_external(function, "%s", os.str().c_str());
    }

    uint64_t result;
    external_fcn_t targetFunction = (external_fcn_t) externalDispatcher->resolveSymbol(function->getName());
    if (!targetFunction) {
        std::stringstream ss;
        ss << "Could not find address of external function " << function->getName().str();
        terminateState(state, ss.str());
        return;
    }

    std::stringstream ss;
    if (!externalDispatcher->call(targetFunction, cas, &result, ss)) {
        ss << ": " << function->getName().str();
        terminateState(state, ss.str());
        return;
    }

    Type *resultType = target->inst->getType();

    if (resultType != Type::getVoidTy(function->getContext())) {
        ref<Expr> resultExpr;
        auto resultWidth = getWidthForLLVMType(resultType);
        switch (resultWidth) {
            case Expr::Bool:
                resultExpr = ConstantExpr::create(result & 1, resultWidth);
            case Expr::Int8:
                resultExpr = ConstantExpr::create((uint8_t) result, resultWidth);
                break;
            case Expr::Int16:
                resultExpr = ConstantExpr::create((uint16_t) result, resultWidth);
                break;
            case Expr::Int32:
                resultExpr = ConstantExpr::create((uint32_t) result, resultWidth);
                break;
            case Expr::Int64:
                resultExpr = ConstantExpr::create((uint64_t) result, resultWidth);
                break;
            default:
                abort();
        }

        state.bindLocal(target, resultExpr);
    }
}

/***/

void Executor::executeAlloc(ExecutionState &state, ref<Expr> size, bool isLocal, KInstruction *target, bool zeroMemory,
                            const ObjectStatePtr &reallocFrom) {
    size = state.toUnique(size);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(size)) {
        auto mo = ObjectState::allocate(0, CE->getZExtValue(), false);
        if (!mo) {
            state.bindLocal(target, ConstantExpr::alloc(0, Context::get().getPointerWidth()));
        } else {
            state.bindObject(mo, isLocal);
            state.bindLocal(target, mo->getBaseExpr());

            if (reallocFrom) {
                unsigned count = std::min(reallocFrom->getSize(), mo->getSize());
                for (unsigned i = 0; i < count; i++) {
                    mo->write(i, reallocFrom->read8(i));
                }
                state.addressSpace.unbindObject(reallocFrom->getKey());
            }
        }
    } else {
        pabort("S2E should not cause allocs with symbolic size");
        abort();
    }
}

template <typename T>
void Executor::writeAndNotify(ExecutionState &state, const ObjectStatePtr &wos, T address, ref<Expr> &value) {
    bool oldAllConcrete = wos->isAllConcrete();

    wos->write(address, value);

    bool newAllConcrete = wos->isAllConcrete();

    if ((oldAllConcrete != newAllConcrete) && (wos->notifyOnConcretenessChange())) {
        state.addressSpaceSymbolicStatusChange(wos, newAllConcrete);
    }
}

ref<Expr> Executor::executeMemoryOperationOverlapped(ExecutionState &state, bool isWrite, uint64_t concreteAddress,
                                                     ref<Expr> value /* undef if read */, unsigned bytes) {
    ObjectStateConstPtr os;
    ref<Expr> readResult;
    const bool littleEndian = Context::get().isLittleEndian();

    for (unsigned i = 0; i < bytes; ++i) {
        bool fastInBounds = false;
        bool success = state.addressSpace.findObject(concreteAddress, 1, os, fastInBounds);
        check(success && fastInBounds, "Could not resolve concrete memory address");

        uint64_t offset = os->getOffset(concreteAddress);
        ref<ConstantExpr> eoffset = ConstantExpr::create(offset, Expr::Int64);

        if (isWrite) {
            unsigned idx = littleEndian ? i : (bytes - i - 1);
            ref<Expr> Byte = ExtractExpr::create(value, 8 * idx, Expr::Int8);

            executeMemoryOperation(state, os, true, eoffset, Byte, Expr::Int8);
        } else {
            ref<Expr> Byte = executeMemoryOperation(state, os, false, eoffset, NULL, Expr::Int8);
            if (i == 0) {
                readResult = Byte;
            } else {
                readResult = littleEndian ? ConcatExpr::create(Byte, readResult) : ConcatExpr::create(readResult, Byte);
            }
        }

        ++concreteAddress;
    }

    if (!isWrite) {
        return readResult;
    } else {
        return NULL;
    }
}

ref<Expr> Executor::executeMemoryOperation(ExecutionState &state, const ObjectStateConstPtr &os, bool isWrite,
                                           uint64_t offset, ref<Expr> value /* undef if read */, Expr::Width type) {
    if (isWrite) {
        if (os->isReadOnly()) {
            terminateState(state, "memory error: object read only");
        } else {
            auto wos = state.addressSpace.getWriteable(os);
            if (wos->isSharedConcrete()) {
                if (!dyn_cast<ConstantExpr>(value)) {
                    std::stringstream ss;
                    ss << "write to always concrete memory name:" << os->getName() << " offset=" << offset;
                    auto s = ss.str();
                    value = state.toConstant(value, s.c_str());
                }
            }

            // Write the value and send a notification if the object changed
            // its concrete/symbolic status.
            writeAndNotify(state, wos, offset, value);
        }
    } else {
        ref<Expr> result = os->read(offset, type);
        return result;
    }

    return nullptr;
}

ref<Expr> Executor::executeMemoryOperation(ExecutionState &state, const ObjectStateConstPtr &os, bool isWrite,
                                           ref<Expr> offset, ref<Expr> value /* undef if read */, Expr::Width type) {
    if (isWrite) {
        if (os->isReadOnly()) {
            terminateState(state, "memory error: object read only");
        } else {
            auto wos = state.addressSpace.getWriteable(os);
            if (wos->isSharedConcrete()) {
                if (!dyn_cast<ConstantExpr>(offset) || !dyn_cast<ConstantExpr>(value)) {
                    std::stringstream ss1, ss2;
                    ss1 << "write to always concrete memory name:" << os->getName() << " offset:";
                    ss2 << "write to always concrete memory name:" << os->getName() << " value:";

                    auto s1 = ss1.str();
                    auto s2 = ss2.str();
                    offset = state.toConstant(offset, s1.c_str());
                    value = state.toConstant(value, s2.c_str());
                }
            }

            // Write the value and send a notification if the object changed
            // its concrete/symbolic status.
            writeAndNotify(state, wos, offset, value);
        }
    } else {
        if (os->isSharedConcrete()) {
            if (!dyn_cast<ConstantExpr>(offset)) {
                std::stringstream ss;
                ss << "Read from always concrete memory name:" << os->getName() << " offset=" << offset;

                offset = state.toConstant(offset, ss.str().c_str());
            }
        }
        ref<Expr> result = os->read(offset, type);
        return result;
    }

    return NULL;
}

void Executor::executeMemoryOperation(ExecutionState &state, bool isWrite, ref<Expr> address,
                                      ref<Expr> value /* undef if read */, KInstruction *target /* undef if write */) {
    Expr::Width type = (isWrite ? value->getWidth() : getWidthForLLVMType(target->inst->getType()));
    unsigned bytes = Expr::getMinBytesForWidth(type);

    if (SimplifySymIndices) {
        if (!isa<ConstantExpr>(address))
            address = state.constraints().simplifyExpr(address);
        if (isWrite && !isa<ConstantExpr>(value))
            value = state.constraints().simplifyExpr(value);
    }

    // fast path: single in-bounds resolution
    ObjectStateConstPtr os;
    bool success = false;
    bool fastInBounds = false;

    /////////////////////////////////////////////////////////////
    // Fast pattern-matching of addresses
    // Avoids calling the constraint solver for simple cases
    if (isa<ConstantExpr>(address)) {
        auto ce = dyn_cast<ConstantExpr>(address)->getZExtValue();
        success = state.addressSpace.findObject(ce, bytes, os, fastInBounds);
        if (!success) {
            // Trying to access a concrete address that is not mapped in KLEE
            abort();
        }
    } else {
        uint64_t base;
        ref<Expr> offset;
        unsigned offsetSize;
        bool ok;
        if (UseExprSimplifier) {
            ok = state.getSimplifier().getBaseOffset(address, base, offset, offsetSize);
        } else {
            ok = state.getSimplifier().getBaseOffsetFast(address, base, offset, offsetSize);
        }

        if (ok) {
            bool tmp;
            if (state.addressSpace.findObject(base, 1, os, tmp)) {
                if (offsetSize <= os->getSize()) {
                    fastInBounds = true;
                    success = true;
                }
            }
        }
    }

    if (success) {
        ref<Expr> result;
        if (fastInBounds) {
            // Either a concrete address or some special types of symbolic addresses
            if (auto CE = dyn_cast<ConstantExpr>(address)) {
                uint64_t offset = os->getOffsetExpr(CE->getZExtValue());
                result = executeMemoryOperation(state, os, isWrite, offset, value, type);
            } else {
                ref<Expr> offset = os->getOffsetExpr(address);
                result = executeMemoryOperation(state, os, isWrite, offset, value, type);
            }
        } else {
            // Can only be a concrete address that spans multiple pages.
            // This can happen only if the page was split before.
            ref<ConstantExpr> concreteAddress = dyn_cast<ConstantExpr>(address);
            assert(!concreteAddress.isNull());
            result = executeMemoryOperationOverlapped(state, isWrite, concreteAddress->getZExtValue(), value, bytes);
        }
        if (!isWrite) {
            state.bindLocal(target, result);
        }
        return;
    }

    /////////////////////////////////////////////////////////////
    // At this point, we can only have a symbolic address

    // Pick a concrete address
    klee::ref<klee::ConstantExpr> concreteAddress;

    concreteAddress = dyn_cast<ConstantExpr>(state.concolics->evaluate(address));
    assert(!concreteAddress.isNull() && "Could not evaluate address");

    /////////////////////////////////////////////////////////////
    // Use the concrete address to determine which page
    // we handle in the current state.
    success = state.addressSpace.findObject(concreteAddress->getZExtValue(), type, os, fastInBounds);
    assert(success);

    // Split the object if necessary
    if (os->isSplittable()) {
        ResolutionList rl;
        success = state.addressSpace.splitMemoryObject(state, os, rl);
        assert(success && "Could not split memory object");

        // Resolve again, we'll get the subpage this time
        success = state.addressSpace.findObject(concreteAddress->getZExtValue(), type, os, fastInBounds);
        assert(success && "Could not resolve concrete memory address");
    }

    /////////////////////////////////////////////////////////////
    // We need to keep the address symbolic to avoid blowup.
    // For that, add a constraint that will ensure that next time, we get a different memory object.
    // Constrain the symbolic address so that it falls
    // into the memory page determined by the concrete assignment.
    // This concerns the base address, which may overlap the next page,
    // depending on the size of the access.
    klee::ref<klee::Expr> condition =
        AndExpr::create(UgeExpr::create(address, os->getBaseExpr()),
                        UltExpr::create(address, AddExpr::create(os->getBaseExpr(), os->getSizeExpr())));

    assert(state.concolics->evaluate(condition)->isTrue());

    StatePair branches = fork(state, condition);

    assert(branches.first == &state);
    if (branches.second) {
        // The forked state will have to re-execute the memory op
        branches.second->pc = branches.second->prevPC;
    }

    notifyFork(state, condition, branches);

    /////////////////////////////////////////////////////////////
    // A symbolic address that dereferences a concrete memory page
    // will not be handled byte by byte by the softmmu and execution
    // will end up here. Fork the overlapping cases in order to
    // avoid missing states.
    unsigned overlappedBytes = bytes - 1;
    if (overlappedBytes > 0) {
        uintptr_t limit = os->getAddress() + os->getSize() - overlappedBytes;
        klee::ref<klee::Expr> overlappedCondition;

        overlappedCondition = UltExpr::create(address, klee::ConstantExpr::create(limit, address->getWidth()));

        if (!fastInBounds) {
            overlappedCondition = NotExpr::create(overlappedCondition);
        }

        StatePair branches = fork(state, overlappedCondition);
        auto forkedState = branches.first == &state ? branches.second : branches.first;
        if (forkedState) {
            // The forked state will have to re-execute the memory op
            forkedState->pc = forkedState->prevPC;
        }

        notifyFork(state, overlappedCondition, branches);
    }

    /////////////////////////////////////////////////////////////
    // The current concrete address does not overlap.
    if (fastInBounds) {
        ref<Expr> offset = os->getOffsetExpr(address);
        ref<Expr> result = executeMemoryOperation(state, os, isWrite, offset, value, type);

        if (!isWrite) {
            state.bindLocal(target, result);
        }

        return;
    }

    /////////////////////////////////////////////////////////////
    // The current concrete address overlaps
    // Fork to ensure that all overlapping cases will be considered
    condition = EqExpr::create(address, concreteAddress);

    // The number of subsequent forks is constrained by the overlappedCondition
    branches = fork(state, condition);
    assert(branches.first == &state);
    if (branches.second) {
        // The forked state will have to re-execute the memory op
        branches.second->pc = branches.second->prevPC;
    }

    notifyFork(state, condition, branches);

    ref<Expr> result = executeMemoryOperationOverlapped(state, isWrite, concreteAddress->getZExtValue(), value, bytes);

    if (!isWrite) {
        state.bindLocal(target, result);
    }

    return;
}

void Executor::addSpecialFunctionHandler(Function *function, FunctionHandler handler) {
    specialFunctionHandler->addUHandler(function, handler);
}

Expr::Width Executor::getWidthForLLVMType(llvm::Type *type) const {
    return kmodule->dataLayout->getTypeSizeInBits(type);
}
