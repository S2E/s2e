//===-- ExecutionState.cpp ------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ExecutionState.h"

#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"

#include "klee/Expr.h"

#include "klee/Memory.h"
#include "klee/util/ExprPPrinter.h"

#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdarg.h>

using namespace llvm;
using namespace klee;

namespace klee {
cl::opt<bool> DebugLogStateMerge("debug-log-state-merge");

cl::opt<bool> ValidateSimplifier("validate-expr-simplifier",
                                 cl::desc("Checks that the simplification algorithm produced correct expressions"),
                                 cl::init(false));

cl::opt<bool> UseExprSimplifier("use-expr-simplifier", cl::desc("Apply expression simplifier for new expressions"),
                                cl::init(true));
}

/***/

StackFrame::StackFrame(KInstIterator _caller, KFunction *_kf) : caller(_caller), kf(_kf), callPathNode(0), varargs(0) {
    locals = new Cell[kf->numRegisters];
}

StackFrame::StackFrame(const StackFrame &s)
    : caller(s.caller), kf(s.kf), callPathNode(s.callPathNode), allocas(s.allocas), varargs(s.varargs) {
    locals = new Cell[s.kf->numRegisters];
    for (unsigned i = 0; i < s.kf->numRegisters; i++)
        locals[i] = s.locals[i];
}

StackFrame::~StackFrame() {
    delete[] locals;
}

/***/

BitfieldSimplifier ExecutionState::s_simplifier;

ExecutionState::ExecutionState(KFunction *kf)
    : fakeState(false), pc(kf->instructions), prevPC(pc), addressSpace(this), queryCost(0.), forkDisabled(false),
      ptreeNode(0), concolics(new Assignment(true)) {
    pushFrame(0, kf);
}

ExecutionState::ExecutionState(const std::vector<ref<Expr>> &assumptions)
    : fakeState(true), constraints(assumptions), addressSpace(this), queryCost(0.), ptreeNode(0),
      concolics(new Assignment(true)) {
}

ExecutionState::~ExecutionState() {
    while (!stack.empty())
        popFrame();
}

ExecutionState *ExecutionState::clone() {
    ExecutionState *state = new ExecutionState(*this);
    state->addressSpace.state = state;
    state->concolics = new Assignment(true);
    return state;
}

void ExecutionState::addressSpaceChange(const MemoryObject *, const ObjectState *, ObjectState *) {
}

void ExecutionState::addressSpaceObjectSplit(const ObjectState *oldObject,
                                             const std::vector<ObjectState *> &newObjects) {
}

void ExecutionState::addressSpaceSymbolicStatusChange(ObjectState *object, bool becameConcrete) {
}

ExecutionState *ExecutionState::branch() {
    ExecutionState *falseState = clone();
    return falseState;
}

void ExecutionState::pushFrame(KInstIterator caller, KFunction *kf) {
    stack.push_back(StackFrame(caller, kf));
}

void ExecutionState::popFrame() {
    StackFrame &sf = stack.back();
    for (std::vector<const MemoryObject *>::iterator it = sf.allocas.begin(), ie = sf.allocas.end(); it != ie; ++it)
        addressSpace.unbindObject(*it);
    stack.pop_back();
}

///

std::string ExecutionState::getFnAlias(std::string fn) {
    std::map<std::string, std::string>::iterator it = fnAliases.find(fn);
    if (it != fnAliases.end())
        return it->second;
    else
        return "";
}

void ExecutionState::addFnAlias(std::string old_fn, std::string new_fn) {
    fnAliases[old_fn] = new_fn;
}

void ExecutionState::removeFnAlias(std::string fn) {
    fnAliases.erase(fn);
}

/**/

llvm::raw_ostream &klee::operator<<(llvm::raw_ostream &os, const MemoryMap &mm) {
    os << "{";
    MemoryMap::iterator it = mm.begin();
    MemoryMap::iterator ie = mm.end();
    if (it != ie) {
        os << "MO" << it->first->id << ":" << it->second;
        for (++it; it != ie; ++it)
            os << ", MO" << it->first->id << ":" << it->second;
    }
    os << "}";
    return os;
}

bool ExecutionState::merge(const ExecutionState &b) {
    if (DebugLogStateMerge)
        llvm::errs() << "-- attempting merge of A:" << this << " with B:" << &b << "--\n";
    if (pc != b.pc)
        return false;

    // XXX is it even possible for these to differ? does it matter? probably
    // implies difference in object states?
    if (symbolics != b.symbolics)
        return false;

    {
        std::vector<StackFrame>::const_iterator itA = stack.begin();
        std::vector<StackFrame>::const_iterator itB = b.stack.begin();
        while (itA != stack.end() && itB != b.stack.end()) {
            // XXX vaargs?
            if (itA->caller != itB->caller || itA->kf != itB->kf)
                return false;
            ++itA;
            ++itB;
        }
        if (itA != stack.end() || itB != b.stack.end())
            return false;
    }

    std::set<ref<Expr>> aConstraints = constraints.getConstraintSet();
    std::set<ref<Expr>> bConstraints = b.constraints.getConstraintSet();
    std::set<ref<Expr>> commonConstraints, aSuffix, bSuffix;
    std::set_intersection(aConstraints.begin(), aConstraints.end(), bConstraints.begin(), bConstraints.end(),
                          std::inserter(commonConstraints, commonConstraints.begin()));
    std::set_difference(aConstraints.begin(), aConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(aSuffix, aSuffix.end()));
    std::set_difference(bConstraints.begin(), bConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(bSuffix, bSuffix.end()));
    if (DebugLogStateMerge) {
        llvm::errs() << "\tconstraint prefix: [";
        for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
            llvm::errs() << *it << ", ";
        llvm::errs() << "]\n";
        llvm::errs() << "\tA suffix: [";
        for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it)
            llvm::errs() << *it << ", ";
        llvm::errs() << "]\n";
        llvm::errs() << "\tB suffix: [";
        for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it)
            llvm::errs() << *it << ", ";
        llvm::errs() << "]\n";
    }

    // We cannot merge if addresses would resolve differently in the
    // states. This means:
    //
    // 1. Any objects created since the branch in either object must
    // have been free'd.
    //
    // 2. We cannot have free'd any pre-existing object in one state
    // and not the other

    if (DebugLogStateMerge) {
        llvm::errs() << "\tchecking object states\n";
        llvm::errs() << "A: " << addressSpace.objects << "\n";
        llvm::errs() << "B: " << b.addressSpace.objects << "\n";
    }

    std::set<const MemoryObject *> mutated;
    MemoryMap::iterator ai = addressSpace.objects.begin();
    MemoryMap::iterator bi = b.addressSpace.objects.begin();
    MemoryMap::iterator ae = addressSpace.objects.end();
    MemoryMap::iterator be = b.addressSpace.objects.end();
    for (; ai != ae && bi != be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    llvm::errs() << "\t\tB misses binding for: " << ai->first->id << "\n";
                } else {
                    llvm::errs() << "\t\tA misses binding for: " << bi->first->id << "\n";
                }
            }
            return false;
        }
        if (ai->second != bi->second) {
            if (DebugLogStateMerge)
                llvm::errs() << "\t\tmutated: " << ai->first->id << "\n";
            mutated.insert(ai->first);
        }
    }
    if (ai != ae || bi != be) {
        if (DebugLogStateMerge)
            llvm::errs() << "\t\tmappings differ\n";
        return false;
    }

    // merge stack

    ref<Expr> inA = ConstantExpr::alloc(1, Expr::Bool);
    ref<Expr> inB = ConstantExpr::alloc(1, Expr::Bool);
    for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it)
        inA = AndExpr::create(inA, *it);
    for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it)
        inB = AndExpr::create(inB, *it);

    // XXX should we have a preference as to which predicate to use?
    // it seems like it can make a difference, even though logically
    // they must contradict each other and so inA => !inB

    std::vector<StackFrame>::iterator itA = stack.begin();
    std::vector<StackFrame>::const_iterator itB = b.stack.begin();
    for (; itA != stack.end(); ++itA, ++itB) {
        StackFrame &af = *itA;
        const StackFrame &bf = *itB;
        for (unsigned i = 0; i < af.kf->numRegisters; i++) {
            ref<Expr> &av = af.locals[i].value;
            const ref<Expr> &bv = bf.locals[i].value;
            if (av.isNull() || bv.isNull()) {
                // if one is null then by implication (we are at same pc)
                // we cannot reuse this local, so just ignore
            } else {
                av = SelectExpr::create(inA, av, bv);
            }
        }
    }

    for (std::set<const MemoryObject *>::iterator it = mutated.begin(), ie = mutated.end(); it != ie; ++it) {
        const MemoryObject *mo = *it;
        const ObjectState *os = addressSpace.findObject(mo);
        const ObjectState *otherOS = b.addressSpace.findObject(mo);
        assert(os && !os->readOnly && "objects mutated but not writable in merging state");
        assert(otherOS);

        ObjectState *wos = addressSpace.getWriteable(mo, os);
        for (unsigned i = 0; i < mo->size; i++) {
            ref<Expr> av = wos->read8(i);
            ref<Expr> bv = otherOS->read8(i);
            wos->write(i, SelectExpr::create(inA, av, bv));
        }
    }

    // XXX: check incremental mode here
    assert(false && "Check incremental mode");
    constraints = ConstraintManager();
    for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
        constraints.addConstraint(*it);
    constraints.addConstraint(OrExpr::create(inA, inB));

    return true;
}

void ExecutionState::printStack(KInstruction *target, std::stringstream &msg) const {
    msg << "Stack: \n";
    unsigned idx = 0;
    for (ExecutionState::stack_ty::const_reverse_iterator it = stack.rbegin(), ie = stack.rend(); it != ie; ++it) {
        const StackFrame &sf = *it;
        Function *f = sf.kf->function;

        msg << "\t#" << idx++ << " " << std::setw(8) << std::setfill('0') << " in " << f->getName().str() << " (";

        // Yawn, we could go up and print varargs if we wanted to.
        unsigned index = 0;
        for (Function::arg_iterator ai = f->arg_begin(), ae = f->arg_end(); ai != ae; ++ai) {
            if (ai != f->arg_begin())
                msg << ", ";

            msg << ai->getName().str();
            // XXX should go through function
            ref<Expr> value = sf.locals[sf.kf->getArgRegister(index++)].value;
            msg << " [" << concolics->evaluate(value) << "]";
        }
        msg << ")";

        msg << "\n";

        target = sf.caller;
    }
}

bool ExecutionState::getSymbolicSolution(std::vector<std::pair<std::string, std::vector<unsigned char>>> &res) {
    for (unsigned i = 0; i != symbolics.size(); ++i) {
        const MemoryObject *mo = symbolics[i].first;
        const Array *arr = symbolics[i].second;
        std::vector<unsigned char> data;
        for (unsigned s = 0; s < arr->getSize(); ++s) {
            ref<Expr> e = concolics->evaluate(arr, s);
            if (!isa<ConstantExpr>(e)) {
                (*klee_warning_stream) << "Failed to evaluate concrete value for " << arr->getName() << "[" << s
                                       << "]: " << e << "\n";
                (*klee_warning_stream) << "  Symbolics (" << symbolics.size() << "):\n";
                for (auto it = symbolics.begin(); it != symbolics.end(); it++) {
                    (*klee_warning_stream) << "    " << it->second->getName() << "\n";
                }
                (*klee_warning_stream) << "  Assignments (" << concolics->bindings.size() << "):\n";
                for (auto it = concolics->bindings.begin(); it != concolics->bindings.end(); it++) {
                    (*klee_warning_stream) << "    " << it->first->getName() << "\n";
                }
                klee_warning_stream->flush();
                assert(false && "Failed to evaluate concrete value");
            }

            uint8_t val = dyn_cast<ConstantExpr>(e)->getZExtValue();
            data.push_back(val);
        }

        res.push_back(std::make_pair(mo->name, data));
    }

    return true;
}

ref<Expr> ExecutionState::simplifyExpr(const ref<Expr> &e) const {
    if (!UseExprSimplifier) {
        return e;
    }

    ref<Expr> simplified = s_simplifier.simplify(e);

    if (ValidateSimplifier) {
        bool isEqual;

        ref<Expr> originalConcrete = concolics->evaluate(e);
        ref<Expr> simplifiedConcrete = concolics->evaluate(simplified);
        isEqual = originalConcrete == simplifiedConcrete;

        if (!isEqual) {
            llvm::errs() << "Error in expression simplifier:" << '\n';
            e->dump();
            llvm::errs() << "!=" << '\n';
            simplified->dump();
            abort();
        }
    }

    return simplified;
}

///
/// \brief Concretize the given expression, and return a possible constant value.
/// \param e the expression to concretized
/// \param reason documentation string stating the reason for concretization
/// \return a concrete value
///
ref<klee::ConstantExpr> ExecutionState::toConstant(ref<Expr> e, const std::string &reason) {
    e = simplifyExpr(e);
    e = constraints.simplifyExpr(e);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e))
        return CE;

    ref<ConstantExpr> value;

    ref<Expr> evalResult = concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    value = dyn_cast<ConstantExpr>(evalResult);

    std::string s;
    raw_string_ostream os(s);

    os << "silently concretizing ";

    const KInstruction *ki = prevPC;
    if (ki && ki->inst) {
        os << "(instruction: " << ki->inst->getParent()->getParent()->getName().str() << ": " << *ki->inst << ") ";
    }

    os << "(reason: " << reason << ") expression " << e << " to value " << value;

    klee_warning_external(reason.c_str(), "%s", os.str().c_str());

    addConstraint(EqExpr::create(e, value));

    return value;
}

// This API does not add a constraint
ref<klee::ConstantExpr> ExecutionState::toConstantSilent(ref<Expr> e) {
    ref<Expr> evalResult = concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    return dyn_cast<ConstantExpr>(evalResult);
}

void ExecutionState::addConstraint(const ref<Expr> &constraint) {
    auto expr = simplifyExpr(constraint);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        assert(CE->isTrue() && "attempt to add invalid constraint");
        abort();
    }

    auto ce = concolics->evaluate(expr);

    if (!ce->isTrue()) {
        assert(false && "Constraint does not evaluate to true");
        abort();
    }

    constraints.addConstraint(expr);
}

/// \brief Print query to solve state constraints
/// Will print query in format understandable by kleaver.
///
/// \param os output stream
void ExecutionState::dumpQuery(llvm::raw_ostream &os) const {
    std::vector<const Array *> symbObjects;
    for (unsigned i = 0; i < symbolics.size(); ++i) {
        symbObjects.push_back(symbolics[i].second);
    }

    auto printer = std::unique_ptr<ExprPPrinter>(ExprPPrinter::create(os));

    Query query(constraints, ConstantExpr::alloc(0, Expr::Bool));
    printer->printQuery(os, query.constraints, query.expr, 0, 0, &symbObjects[0], &symbObjects[0] + symbObjects.size());
    os.flush();
}

std::shared_ptr<TimingSolver> ExecutionState::solver() const {
    return SolverManager::solver(*this);
}
