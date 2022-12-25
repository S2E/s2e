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
#include "klee/ExternalDispatcher.h"
#include "klee/Memory.h"
#include "klee/Searcher.h"
#include "klee/SolverFactory.h"
#include "klee/Stats/CoreStats.h"
#include "klee/Stats/SolverStats.h"
#include "klee/Stats/TimerStatIncrementer.h"
#include "klee/TimingSolver.h"
#include "SpecialFunctionHandler.h"

#include "klee/Config/config.h"
#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/FloatEvaluation.h"
#include "klee/Internal/System/Time.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprUtil.h"
#include "klee/util/GetElementPtrTypeIterator.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
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

#include <sys/mman.h>

#include <cxxabi.h>
#include <errno.h>
#include <inttypes.h>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool> SimplifySymIndices("simplify-sym-indices", cl::init(true));

cl::opt<bool> SuppressExternalWarnings("suppress-external-warnings", cl::init(true));

cl::opt<bool> NoExternals("no-externals", cl::desc("Do not allow external functin calls"));
} // namespace

namespace klee {
extern cl::opt<bool> UseExprSimplifier;
} // namespace klee

Executor::Executor(LLVMContext &context)
    : kmodule(0), searcher(0), externalDispatcher(new ExternalDispatcher()), specialFunctionHandler(0) {
}

const Module *Executor::setModule(llvm::Module *module) {
    assert(!kmodule && module && "can only register one module"); // XXX gross

    kmodule = KModule::create(module);

    // Initialize the context.
    auto TD = kmodule->getDataLayout();
    Context::initialize(TD->isLittleEndian(), (Expr::Width) TD->getPointerSizeInBits());

    specialFunctionHandler = new SpecialFunctionHandler(*this);

    specialFunctionHandler->prepare(*module);

    kmodule->prepare();

    specialFunctionHandler->bind(*module);

    return module;
}

Executor::~Executor() {
    delete externalDispatcher;
    if (specialFunctionHandler)
        delete specialFunctionHandler;
}

/***/

void Executor::initializeGlobalObject(ExecutionState &state, const ObjectStatePtr &os, const Constant *c,
                                      unsigned offset) {
    auto targetData = kmodule->getDataLayout();
    if (const ConstantVector *cp = dyn_cast<ConstantVector>(c)) {
        unsigned elementSize = targetData->getTypeStoreSize(cp->getType()->getElementType());
        for (unsigned i = 0, e = cp->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, cp->getOperand(i), offset + i * elementSize);
    } else if (isa<ConstantAggregateZero>(c)) {
        unsigned i, size = targetData->getTypeStoreSize(c->getType());
        for (i = 0; i < size; i++)
            os->write(offset + i, (uint8_t) 0);
    } else if (const ConstantArray *ca = dyn_cast<ConstantArray>(c)) {
        unsigned elementSize = targetData->getTypeStoreSize(ca->getType()->getElementType());
        for (unsigned i = 0, e = ca->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, ca->getOperand(i), offset + i * elementSize);
    } else if (const ConstantStruct *cs = dyn_cast<ConstantStruct>(c)) {
        const StructLayout *sl = targetData->getStructLayout(cast<StructType>(cs->getType()));
        for (unsigned i = 0, e = cs->getNumOperands(); i != e; ++i)
            initializeGlobalObject(state, os, cs->getOperand(i), offset + sl->getElementOffset(i));
    } else if (const ConstantDataSequential *cds = dyn_cast<ConstantDataSequential>(c)) {
        unsigned elementSize = targetData->getTypeStoreSize(cds->getElementType());
        for (unsigned i = 0, e = cds->getNumElements(); i != e; ++i)
            initializeGlobalObject(state, os, cds->getElementAsConstant(i), offset + i * elementSize);
    } else if (!isa<UndefValue>(c) && !isa<MetadataAsValue>(c)) {
        unsigned StoreBits = targetData->getTypeStoreSizeInBits(c->getType());
        ref<ConstantExpr> C = kmodule->evalConstant(globalAddresses, c);

        // Extend the constant if necessary;
        assert(StoreBits >= C->getWidth() && "Invalid store size!");
        if (StoreBits > C->getWidth())
            C = C->ZExt(StoreBits);

        os->write(offset, C);
    }
}

void Executor::initializeGlobals(ExecutionState &state) {
    auto m = kmodule->getModule();

    if (m->getModuleInlineAsm() != "")
        klee_warning("executable has module level assembly (ignoring)");

    // represent function globals using the address of the actual llvm function
    // object. given that we use malloc to allocate memory in states this also
    // ensures that we won't conflict. we don't need to allocate a memory object
    // since reading/writing via a function pointer is unsupported anyway.
    for (auto i = m->begin(), ie = m->end(); i != ie; ++i) {
        auto f = &*i;
        ref<ConstantExpr> addr(0);

        // If the symbol has external weak linkage then it is implicitly
        // not defined in this module; if it isn't resolvable then it
        // should be null.
        if (f->hasExternalWeakLinkage() && !externalDispatcher->resolveSymbol(f->getName().str())) {
            addr = Expr::createPointer(0);
        } else {
            addr = Expr::createPointer((uintptr_t) (void *) f);
        }

        globalAddresses.insert(std::make_pair(f, addr));
    }

// Disabled, we don't want to promote use of live externals.
#ifdef HAVE_CTYPE_EXTERNALS
#ifndef WINDOWS
#ifndef DARWIN
    /* From /usr/include/errno.h: it [errno] is a per-thread variable. */
    int *errno_addr = __errno_location();
    state.addExternalObject((void *) errno_addr, sizeof *errno_addr, false);

    /* from /usr/include/ctype.h:
         These point into arrays of 384, so they can be indexed by any `unsigned
         char' value [0,255]; by EOF (-1); or by any `signed char' value
         [-128,-1).  ISO C requires that the ctype functions work for `unsigned */
    const uint16_t **addr = __ctype_b_loc();
    state.addExternalObject((void *) (*addr - 128), 384 * sizeof **addr, true);
    state.addExternalObject(addr, sizeof(*addr), true);

    const int32_t **lower_addr = __ctype_tolower_loc();
    state.addExternalObject((void *) (*lower_addr - 128), 384 * sizeof **lower_addr, true);
    state.addExternalObject(lower_addr, sizeof(*lower_addr), true);

    const int32_t **upper_addr = __ctype_toupper_loc();
    state.addExternalObject((void *) (*upper_addr - 128), 384 * sizeof **upper_addr, true);
    state.addExternalObject(upper_addr, sizeof(*upper_addr), true);
#endif
#endif
#endif

    // allocate and initialize globals, done in two passes since we may
    // need address of a global in order to initialize some other one.

    // allocate memory objects for all globals
    for (Module::const_global_iterator i = m->global_begin(), e = m->global_end(); i != e; ++i) {
        std::map<std::string, void *>::iterator po = predefinedSymbols.find(i->getName().str());
        if (po != predefinedSymbols.end()) {
            // This object was externally defined
            globalAddresses.insert(
                std::make_pair(&*i, ConstantExpr::create((uint64_t) po->second, sizeof(void *) * 8)));

        } else if (i->isDeclaration()) {
            // FIXME: We have no general way of handling unknown external
            // symbols. If we really cared about making external stuff work
            // better we could support user definition, or use the EXE style
            // hack where we check the object file information.

            Type *ty = i->getType()->getPointerElementType();
            uint64_t size = kmodule->getDataLayout()->getTypeStoreSize(ty);

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
                addr = externalDispatcher->resolveSymbol(i->getName().str());

                if (!addr)
                    klee_error("unable to load symbol(%s) while initializing globals.", i->getName().data());

                for (unsigned offset = 0; offset < mo->getSize(); offset++) {
                    mo->write(offset, ((unsigned char *) addr)[offset]);
                }
            }
        } else {
            Type *ty = i->getType()->getPointerElementType();
            uint64_t size = kmodule->getDataLayout()->getTypeStoreSize(ty);
            auto mo = ObjectState::allocate(0, size, false);

            assert(mo && "out of memory");
            state.bindObject(mo, false);
            globalObjects.insert(std::make_pair(&*i, mo->getKey()));
            globalAddresses.insert(std::make_pair(&*i, mo->getBaseExpr()));
        }
    }

    // link aliases to their definitions (if bound)
    for (auto i = m->alias_begin(), ie = m->alias_end(); i != ie; ++i) {
        // Map the alias to its aliasee's address. This works because we have
        // addresses for everything, even undefined functions.
        globalAddresses.insert(std::make_pair(&*i, kmodule->evalConstant(globalAddresses, i->getAliasee())));
    }

    // once all objects are allocated, do the actual initialization
    for (auto i = m->global_begin(), e = m->global_end(); i != e; ++i) {
        if (predefinedSymbols.find(i->getName().str()) != predefinedSymbols.end()) {
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
            return StatePair(&current, nullptr);
        } else {
            return StatePair(nullptr, &current);
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
            return StatePair(&current, nullptr);
        } else {
            if (!current.addConstraint(Expr::createIsZero(condition))) {
                abort();
            }
            return StatePair(nullptr, &current);
        }
    }

    if (keepConditionTrueInCurrentState && !conditionIsTrue) {
        // Recompute concrete values to keep condition true in current state

        // Build constraints where condition must be true
        ConstraintManager tmpConstraints = current.constraints();
        tmpConstraints.addConstraint(condition);

        if (!current.solve(tmpConstraints, *(current.concolics))) {
            // Condition is always false in the current state
            return StatePair(nullptr, &current);
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

    AssignmentPtr concolics = Assignment::create(true);
    if (!current.solve(tmpConstraints, *concolics)) {
        if (conditionIsTrue) {
            return StatePair(&current, nullptr);
        } else {
            return StatePair(nullptr, &current);
        }
    }

    // Branch
    ExecutionState *branchedState;
    notifyBranch(current);
    branchedState = current.clone();
    addedStates.insert(branchedState);

    *klee::stats::forks += 1;

    // Update concrete values for the branched state
    branchedState->concolics = concolics;

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

Executor::StatePair Executor::fork(ExecutionState &current) {
    if (current.forkDisabled) {
        return StatePair(&current, nullptr);
    }

    ExecutionState *clonedState;
    notifyBranch(current);
    clonedState = current.clone();
    addedStates.insert(clonedState);

    // Deep copy concolics.
    clonedState->concolics = Assignment::create(current.concolics);

    return StatePair(&current, clonedState);
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
        return kmodule->getConstant(index);
    } else {
        unsigned index = vnumber;
        StackFrame &sf = state.stack.back();
        //*klee_warning_stream << "op idx=" << std::dec << index << '\n';
        return sf.locals[index];
    }
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

void Executor::executeCall(ExecutionState &state, KInstruction *ki, Function *f, std::vector<ref<Expr>> &arguments) {
    Instruction *i = ki->inst;

    if (f && overridenInternalFunctions.find(f) != overridenInternalFunctions.end()) {
        callExternalFunction(state, ki, f, arguments);
    } else if (f && f->isDeclaration()) {
        switch (f->getIntrinsicID()) {
            case Intrinsic::not_intrinsic:
                // state may be destroyed by this call, cannot touch
                callExternalFunction(state, ki, f, arguments);
                break;

            case Intrinsic::fabs: {
                ref<ConstantExpr> arg = state.toConstant(arguments[0], "floating point");
                if (!fpWidthToSemantics(arg->getWidth()))
                    return terminateState(state, "Unsupported intrinsic llvm.fabs call");

                llvm::APFloat Res(*fpWidthToSemantics(arg->getWidth()), arg->getAPValue());
                Res = llvm::abs(Res);

                state.bindLocal(ki, ConstantExpr::alloc(Res.bitcastToAPInt()));
                break;
            }

            case Intrinsic::abs: {
                if (isa<VectorType>(i->getOperand(0)->getType()))
                    return terminateState(state, "llvm.abs with vectors is not supported");

                ref<Expr> op = eval(ki, 1, state).value;
                ref<Expr> poison = eval(ki, 2, state).value;

                assert(poison->getWidth() == 1 && "Second argument is not an i1");
                unsigned bw = op->getWidth();

                uint64_t moneVal = APInt(bw, -1, true).getZExtValue();
                uint64_t sminVal = APInt::getSignedMinValue(bw).getZExtValue();

                ref<ConstantExpr> zero = ConstantExpr::create(0, bw);
                ref<ConstantExpr> mone = ConstantExpr::create(moneVal, bw);
                ref<ConstantExpr> smin = ConstantExpr::create(sminVal, bw);

                if (poison->isTrue()) {
                    ref<Expr> issmin = EqExpr::create(op, smin);
                    if (issmin->isTrue())
                        return terminateState(state, "llvm.abs called with poison and INT_MIN");
                }

                // conditions to flip the sign: INT_MIN < op < 0
                ref<Expr> negative = SltExpr::create(op, zero);
                ref<Expr> notsmin = NeExpr::create(op, smin);
                ref<Expr> cond = AndExpr::create(negative, notsmin);

                // flip and select the result
                ref<Expr> flip = MulExpr::create(op, mone);
                ref<Expr> result = SelectExpr::create(cond, flip, op);

                state.bindLocal(ki, result);
                break;
            }

            case Intrinsic::smax:
            case Intrinsic::smin:
            case Intrinsic::umax:
            case Intrinsic::umin: {
                if (isa<VectorType>(i->getOperand(0)->getType()) || isa<VectorType>(i->getOperand(1)->getType()))
                    return terminateState(state, "llvm.{s,u}{max,min} with vectors is not supported");

                ref<Expr> op1 = eval(ki, 1, state).value;
                ref<Expr> op2 = eval(ki, 2, state).value;

                ref<Expr> cond = nullptr;
                if (f->getIntrinsicID() == Intrinsic::smax)
                    cond = SgtExpr::create(op1, op2);
                else if (f->getIntrinsicID() == Intrinsic::smin)
                    cond = SltExpr::create(op1, op2);
                else if (f->getIntrinsicID() == Intrinsic::umax)
                    cond = UgtExpr::create(op1, op2);
                else // (f->getIntrinsicID() == Intrinsic::umin)
                    cond = UltExpr::create(op1, op2);

                ref<Expr> result = SelectExpr::create(cond, op1, op2);
                state.bindLocal(ki, result);
                break;
            }

            case Intrinsic::fshr:
            case Intrinsic::fshl: {
                ref<Expr> op1 = eval(ki, 1, state).value;
                ref<Expr> op2 = eval(ki, 2, state).value;
                ref<Expr> op3 = eval(ki, 3, state).value;
                unsigned w = op1->getWidth();
                assert(w == op2->getWidth() && "type mismatch");
                assert(w == op3->getWidth() && "type mismatch");
                ref<Expr> c = ConcatExpr::create(op1, op2);
                // op3 = zeroExtend(op3 % w)
                op3 = URemExpr::create(op3, ConstantExpr::create(w, w));
                op3 = ZExtExpr::create(op3, w + w);
                if (f->getIntrinsicID() == Intrinsic::fshl) {
                    // shift left and take top half
                    ref<Expr> s = ShlExpr::create(c, op3);
                    state.bindLocal(ki, ExtractExpr::create(s, w, w));
                } else {
                    // shift right and take bottom half
                    // note that LShr and AShr will have same behaviour
                    ref<Expr> s = LShrExpr::create(c, op3);
                    state.bindLocal(ki, ExtractExpr::create(s, 0, w));
                }
                break;
            }

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

        if (InvokeInst *ii = dyn_cast<InvokeInst>(i)) {
            state.transferToBasicBlock(ii->getNormalDest(), i->getParent());
        }
    } else {
        // FIXME: I'm not really happy about this reliance on prevPC but it is ok, I
        // guess. This just done to avoid having to pass KInstIterator everywhere
        // instead of the actual instruction, since we can't make a KInstIterator
        // from just an instruction (unlike LLVM).
        auto kf = kmodule->getKFunction(f);
        state.pushFrame(state.prevPC, kf);
        state.pc = kf->getInstructions();

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
                // size. This happens to work for x86-32 and x86-64, however.
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

/// Compute the true target of a function call, resolving LLVM aliases
/// and bitcasts.
Function *Executor::getTargetFunction(Value *calledVal) {
    SmallPtrSet<const GlobalValue *, 3> Visited;

    Constant *c = dyn_cast<Constant>(calledVal);
    if (!c) {
        return 0;
    }

    while (true) {
        if (GlobalValue *gv = dyn_cast<GlobalValue>(c)) {
            if (!Visited.insert(gv).second) {
                return 0;
            }

            if (Function *f = dyn_cast<Function>(gv)) {
                return f;
            } else if (GlobalAlias *ga = dyn_cast<GlobalAlias>(gv)) {
                c = ga->getAliasee();
            } else {
                return 0;
            }
        } else if (llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(c)) {
            if (ce->getOpcode() == Instruction::BitCast) {
                c = ce->getOperand(0);
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }
}

void Executor::executeInstruction(ExecutionState &state, KInstruction *ki) {
    *klee::stats::instructions += 1;

    Instruction *i = ki->inst;
    switch (i->getOpcode()) {
        // Control flow
        case Instruction::Ret: {
            ReturnInst *ri = cast<ReturnInst>(i);
            KInstIterator kcaller = state.stack.back().caller;
            Instruction *caller = kcaller ? kcaller->inst : nullptr;
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
                    state.transferToBasicBlock(ii->getNormalDest(), caller->getParent());
                } else {
                    state.pc = kcaller;
                    ++state.pc;
                }

                if (!isVoidReturn) {
                    Type *t = caller->getType();
                    if (t != Type::getVoidTy(caller->getContext())) {
                        // may need to do coercion due to bitcasts
                        Expr::Width from = result->getWidth();
                        Expr::Width to = kmodule->getWidthForLLVMType(t);

                        if (from != to) {
                            const CallBase &cs = cast<CallBase>(*caller);

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
                state.transferToBasicBlock(bi->getSuccessor(0), bi->getParent());
            } else {
                // FIXME: Find a way that we don't have this hidden dependency.
                assert(bi->getCondition() == bi->getOperand(0) && "Wrong operand index!");
                ref<Expr> cond = eval(ki, 0, state).value;
                Executor::StatePair branches = fork(state, cond);

                if (branches.first) {
                    branches.first->transferToBasicBlock(bi->getSuccessor(0), bi->getParent());
                }
                if (branches.second) {
                    branches.second->transferToBasicBlock(bi->getSuccessor(1), bi->getParent());
                }

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
            notifyFork(state, condition, sp);
            cond = concreteCond;

            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(cond)) {
                // Somewhat gross to create these all the time, but fine till we
                // switch to an internal rep.
                llvm::IntegerType *Ty = cast<IntegerType>(si->getCondition()->getType());
                ConstantInt *ci = ConstantInt::get(Ty, CE->getZExtValue());
                SwitchInst::CaseIt cit = si->findCaseValue(ci);
                state.transferToBasicBlock(cit->getCaseSuccessor(), si->getParent());
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
            // Ignore debug intrinsic calls
            if (isa<DbgInfoIntrinsic>(i)) {
                break;
            }

            const CallBase &cs = cast<CallBase>(*i);
            Value *fp = cs.getCalledOperand();

            unsigned numArgs = cs.arg_size();
            Function *f = getTargetFunction(fp);

            // evaluate arguments
            std::vector<ref<Expr>> arguments;
            arguments.reserve(numArgs);

            for (unsigned j = 0; j < numArgs; ++j) {
                arguments.push_back(eval(ki, j + 1, state).value);
            }

            if (!f) {
                // special case the call with a bitcast case
                llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(fp);

                if (ce && ce->getOpcode() == Instruction::BitCast) {
                    f = dyn_cast<Function>(ce->getOperand(0));
                    assert(f && "XXX unrecognized constant expression in call");
                    const FunctionType *fType =
                        dyn_cast<FunctionType>(cast<PointerType>(f->getType())->getPointerElementType());
                    const FunctionType *ceType =
                        dyn_cast<FunctionType>(cast<PointerType>(ce->getType())->getPointerElementType());
                    check(fType && ceType, "unable to get function type");

                    // XXX check result coercion

                    // XXX this really needs thought and validation
                    unsigned i = 0;
                    for (std::vector<ref<Expr>>::iterator ai = arguments.begin(), ie = arguments.end(); ai != ie;
                         ++ai) {
                        Expr::Width to, from = (*ai)->getWidth();

                        if (i < fType->getNumParams()) {
                            to = kmodule->getWidthForLLVMType(fType->getParamType(i));

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
                if (!constantTarget) {
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
            unsigned elementSize = kmodule->getDataLayout()->getTypeStoreSize(ai->getAllocatedType());
            ref<Expr> size = Expr::createPointer(elementSize);
            if (ai->isArrayAllocation()) {
                ref<Expr> count = eval(ki, 0, state).value;
                count = Expr::createCoerceToPointerType(count);
                size = MulExpr::create(size, count);
            }
            bool isLocal = i->getOpcode() == Instruction::Alloca;
            state.executeAlloc(size, isLocal, ki);
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
            ref<Expr> result =
                ExtractExpr::create(eval(ki, 0, state).value, 0, kmodule->getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }
        case Instruction::ZExt: {
            CastInst *ci = cast<CastInst>(i);
            ref<Expr> result = ZExtExpr::create(eval(ki, 0, state).value, kmodule->getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }
        case Instruction::SExt: {
            CastInst *ci = cast<CastInst>(i);
            ref<Expr> result = SExtExpr::create(eval(ki, 0, state).value, kmodule->getWidthForLLVMType(ci->getType()));
            state.bindLocal(ki, result);
            break;
        }

        case Instruction::IntToPtr: {
            CastInst *ci = cast<CastInst>(i);
            Expr::Width pType = kmodule->getWidthForLLVMType(ci->getType());
            ref<Expr> arg = eval(ki, 0, state).value;
            state.bindLocal(ki, ZExtExpr::create(arg, pType));
            break;
        }
        case Instruction::PtrToInt: {
            CastInst *ci = cast<CastInst>(i);
            Expr::Width iType = kmodule->getWidthForLLVMType(ci->getType());
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
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPTrunc operation");
            uint64_t value = floats::trunc(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPExt: {
            FPExtInst *fi = cast<FPExtInst>(i);
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPExt operation");
            uint64_t value = floats::ext(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPToUI: {
            FPToUIInst *fi = cast<FPToUIInst>(i);
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPToUI operation");
            uint64_t value = floats::toUnsignedInt(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::FPToSI: {
            FPToSIInst *fi = cast<FPToSIInst>(i);
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported FPToSI operation");
            uint64_t value = floats::toSignedInt(arg->getZExtValue(), resultType, arg->getWidth());
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::UIToFP: {
            UIToFPInst *fi = cast<UIToFPInst>(i);
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
            ref<ConstantExpr> arg = state.toConstant(eval(ki, 0, state).value, "floating point");
            if (arg->getWidth() > 64)
                return terminateState(state, "Unsupported UIToFP operation");
            uint64_t value = floats::UnsignedIntToFP(arg->getZExtValue(), resultType);
            state.bindLocal(ki, ConstantExpr::alloc(value, resultType));
            break;
        }

        case Instruction::SIToFP: {
            SIToFPInst *fi = cast<SIToFPInst>(i);
            Expr::Width resultType = kmodule->getWidthForLLVMType(fi->getType());
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
            if (l && r)
                result = ConcatExpr::create(r, ConcatExpr::create(val, l));
            else if (l)
                result = ConcatExpr::create(val, l);
            else if (r)
                result = ConcatExpr::create(r, val);
            else
                result = val;

            state.bindLocal(ki, result);
            break;
        }
        case Instruction::ExtractValue: {
            KGEPInstruction *kgepi = static_cast<KGEPInstruction *>(ki);

            ref<Expr> agg = eval(ki, 0, state).value;

            ref<Expr> result = ExtractExpr::create(agg, kgepi->offset * 8, kmodule->getWidthForLLVMType(i->getType()));

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
            const auto *vt = cast<llvm::FixedVectorType>(iei->getType());
            unsigned EltBits = kmodule->getWidthForLLVMType(vt->getElementType());

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
            const auto *vt = cast<llvm::FixedVectorType>(eei->getVectorOperandType());
            unsigned EltBits = kmodule->getWidthForLLVMType(vt->getElementType());

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

void Executor::deleteState(ExecutionState *state) {
    delete state;
}

void Executor::terminateState(ExecutionState &state) {
    *klee::stats::completedPaths += 1;

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

    if (NoExternals && !okExternals.count(function->getName().str())) {
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
    external_fcn_t targetFunction = (external_fcn_t) externalDispatcher->resolveSymbol(function->getName().str());
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
        auto resultWidth = kmodule->getWidthForLLVMType(resultType);
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

ref<Expr> Executor::executeMemoryOperation(ExecutionState &state, bool isWrite, uint64_t concreteAddress,
                                           ref<Expr> value /* undef if read */, unsigned bytes) {
    auto concretizer = [&](const ref<Expr> &value, const ObjectStateConstPtr &os, size_t offset) {
        return state.toConstant(value, os, offset);
    };

    if (isWrite) {
        assert(Expr::getMinBytesForWidth(value->getWidth()) == bytes);
        if (!state.addressSpace.write(concreteAddress, value, concretizer)) {
            pabort("write failed");
        }
    } else {
        auto ret = state.addressSpace.read(concreteAddress, bytes * 8);
        if (!ret) {
            pabort("read failed");
        }
        return ret;
    }

    return nullptr;
}

void Executor::executeMemoryOperation(ExecutionState &state, bool isWrite, ref<Expr> address,
                                      ref<Expr> value /* undef if read */, KInstruction *target /* undef if write */) {
    Expr::Width type = (isWrite ? value->getWidth() : kmodule->getWidthForLLVMType(target->inst->getType()));
    unsigned bytes = Expr::getMinBytesForWidth(type);

    if (SimplifySymIndices) {
        if (!isa<ConstantExpr>(address))
            address = state.constraints().simplifyExpr(address);
        if (isWrite && !isa<ConstantExpr>(value))
            value = state.constraints().simplifyExpr(value);
    }

    // Concrete address case.
    if (isa<ConstantExpr>(address)) {
        auto ce = dyn_cast<ConstantExpr>(address)->getZExtValue();
        auto result = executeMemoryOperation(state, isWrite, ce, value, bytes);

        if (!isWrite) {
            state.bindLocal(target, result);
        }
        return;
    }

    auto concreteAddress = dyn_cast<ConstantExpr>(state.concolics->evaluate(address));
    assert(concreteAddress && "Could not evaluate address");

    /////////////////////////////////////////////////////////////
    // Use the concrete address to determine which page
    // we handle in the current state.
    ObjectStateConstPtr os;
    bool fastInBounds = false;
    auto success = state.addressSpace.findObject(concreteAddress->getZExtValue(), type, os, fastInBounds);
    if (!success) {
        pabort("could not find memory object");
    }

    // Split the object if necessary
    if (os->isSplittable()) {
        ResolutionList rl;
        success = state.addressSpace.splitMemoryObject(state, os, rl);
        if (!success) {
            pabort("could not split memory object");
        }

        // Resolve again, we'll get the subpage this time
        success = state.addressSpace.findObject(concreteAddress->getZExtValue(), type, os, fastInBounds);
        if (!success) {
            pabort("Could not resolve concrete memory address");
        }
    }

    assert(concreteAddress->getZExtValue() >= os->getAddress());

    ref<Expr> condition;
    // TODO: overflows
    if (concreteAddress->getZExtValue() + bytes <= os->getAddress() + os->getSize()) {
        condition =
            AndExpr::create(UgeExpr::create(address, os->getBaseExpr()),
                            UleExpr::create(AddExpr::create(address, ConstantExpr::create(bytes, address->getWidth())),
                                            AddExpr::create(os->getBaseExpr(), os->getSizeExpr())));

    } else {
        condition = EqExpr::create(address, concreteAddress);
        address = concreteAddress;
    }

    assert(state.concolics->evaluate(condition)->isTrue());

    StatePair branches = fork(state, condition);

    assert(branches.first == &state);
    if (branches.second) {
        // The forked state will have to re-execute the memory op
        branches.second->pc = branches.second->prevPC;
    }

    notifyFork(state, condition, branches);

    if (isa<ConstantExpr>(address)) {
        auto ce = dyn_cast<ConstantExpr>(address)->getZExtValue();
        auto result = executeMemoryOperation(state, isWrite, ce, value, bytes);

        if (!isWrite) {
            state.bindLocal(target, result);
        }
        return;
    }

    auto offset = SubExpr::create(address, os->getBaseExpr());

    if (isWrite) {
        auto wos = state.addressSpace.getWriteable(os);
        wos->write(offset, value);
    } else {
        auto result = os->read(offset, type);
        assert(result);
        state.bindLocal(target, result);
    }
}

void Executor::addSpecialFunctionHandler(Function *function, FunctionHandler handler) {
    specialFunctionHandler->addUHandler(function, handler);
}
