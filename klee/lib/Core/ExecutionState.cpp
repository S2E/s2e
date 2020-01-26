//===-- ExecutionState.cpp ------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ExecutionState.h"
#include "klee/CoreStats.h"

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

namespace klee {

cl::opt<bool> DebugLogStateMerge("debug-log-state-merge");

cl::opt<bool> ValidateSimplifier("validate-expr-simplifier",
                                 cl::desc("Checks that the simplification algorithm produced correct expressions"),
                                 cl::init(false));

cl::opt<bool> UseExprSimplifier("use-expr-simplifier", cl::desc("Apply expression simplifier for new expressions"),
                                cl::init(true));

cl::opt<bool> DebugPrintInstructions("debug-print-instructions", cl::desc("Print instructions during execution."),
                                     cl::init(false));

// This is set to false in order to avoid the overhead of printing large expressions
cl::opt<bool> PrintConcretizedExpression("print-concretized-expression", cl::desc("Print concretized expression."),
                                         cl::init(false));

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
std::set<ObjectKey, ObjectKeyLTS> ExecutionState::s_ignoredMergeObjects;

ExecutionState::ExecutionState(KFunction *kf)
    : fakeState(false), pc(kf->instructions), prevPC(nullptr), addressSpace(this), queryCost(0.), forkDisabled(false),
      concolics(new Assignment(true)) {
    pushFrame(0, kf);
}

ExecutionState::ExecutionState(const std::vector<ref<Expr>> &assumptions)
    : fakeState(true), addressSpace(this), queryCost(0.), concolics(new Assignment(true)) {
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

void ExecutionState::addressSpaceChange(const ObjectKey &key, const ObjectStateConstPtr &oldState,
                                        const ObjectStatePtr &newState) {
}

void ExecutionState::addressSpaceObjectSplit(const ObjectStateConstPtr &oldObject,
                                             const std::vector<ObjectStatePtr> &newObjects) {
}

void ExecutionState::addressSpaceSymbolicStatusChange(const ObjectStatePtr &object, bool becameConcrete) {
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
    for (auto it : sf.allocas) {
        addressSpace.unbindObject(it);
    }
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

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const MemoryMap &mm) {
    os << "{";
    MemoryMap::iterator it = mm.begin();
    MemoryMap::iterator ie = mm.end();
    if (it != ie) {
        os << "MO" << it->first.address << ":" << it->second.get();
        for (++it; it != ie; ++it)
            os << ", MO" << it->first.address << ":" << it->second.get();
    }
    os << "}";
    return os;
}

bool ExecutionState::merge(const ExecutionState &b) {
    auto &m = *klee_message_stream;
    if (DebugLogStateMerge) {
        m << "-- attempting merge of A:" << this << " with B:" << &b << "--\n";
    }

    if (pc != b.pc) {
        if (DebugLogStateMerge) {
            m << "merge failed: different KLEE pc\n" << *(*pc).inst << "\n" << *(*b.pc).inst << "\n";

            std::stringstream ss;
            this->printStack(nullptr, ss);
            b.printStack(nullptr, ss);
            m << ss.str() << "\n";
        }
        return false;
    }

    // XXX is it even possible for these to differ? does it matter? probably
    // implies difference in object states?
    if (symbolics != b.symbolics) {
        if (DebugLogStateMerge) {
            m << "merge failed: different symbolics" << '\n';

            for (auto it : symbolics) {
                m << it->getName() << "\n";
            }
            m << "\n";
            for (auto it : b.symbolics) {
                m << it->getName() << "\n";
            }
        }
        return false;
    }

    {
        auto itA = stack.begin();
        auto itB = b.stack.begin();
        while (itA != stack.end() && itB != b.stack.end()) {
            // XXX vaargs?
            if (itA->caller != itB->caller || itA->kf != itB->kf) {
                if (DebugLogStateMerge) {
                    m << "merge failed: different callstacks" << '\n';
                }
            }
            ++itA;
            ++itB;
        }
        if (itA != stack.end() || itB != b.stack.end()) {
            if (DebugLogStateMerge) {
                m << "merge failed: different callstacks" << '\n';
            }
            return false;
        }
    }

    std::set<ref<Expr>> aConstraints = constraints().getConstraintSet();
    std::set<ref<Expr>> bConstraints = b.constraints().getConstraintSet();
    std::set<ref<Expr>> commonConstraints, aSuffix, bSuffix;

    std::set_intersection(aConstraints.begin(), aConstraints.end(), bConstraints.begin(), bConstraints.end(),
                          std::inserter(commonConstraints, commonConstraints.begin()));

    std::set_difference(aConstraints.begin(), aConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(aSuffix, aSuffix.end()));

    std::set_difference(bConstraints.begin(), bConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(bSuffix, bSuffix.end()));
    if (DebugLogStateMerge) {
        m << "\tconstraint prefix: [";
        for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
            m << *it << ", ";
        m << "]\n";
        m << "\tA suffix: [";
        for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it)
            m << *it << ", ";
        m << "]\n";
        m << "\tB suffix: [";
        for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it)
            m << *it << ", ";
        m << "]" << '\n';
    }

    // We cannot merge if addresses would resolve differently in the
    // states. This means:
    //
    // 1. Any objects created since the branch in either object must
    // have been free'd.
    //
    // 2. We cannot have free'd any pre-existing object in one state
    // and not the other

    std::set<ObjectKey> mutated;
    MemoryMap::iterator ai = addressSpace.objects.begin();
    MemoryMap::iterator bi = b.addressSpace.objects.begin();
    MemoryMap::iterator ae = addressSpace.objects.end();
    MemoryMap::iterator be = b.addressSpace.objects.end();
    for (; ai != ae && bi != be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    m << "\t\tB misses binding for: " << ai->first.address << "\n";
                } else {
                    m << "\t\tA misses binding for: " << bi->first.address << "\n";
                }
            }
            return false;
        }
        if (ai->second != bi->second) {
            if (DebugLogStateMerge)
                llvm::errs() << "\t\tmutated: " << ai->first.address << "\n";
            mutated.insert(ai->first);
        }
    }
    if (ai != ae || bi != be) {
        if (DebugLogStateMerge) {
            m << "\t\tmappings differ\n";
        }
        return false;
    }

    for (; ai != ae && bi != be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    m << "\t\tB misses binding for: " << hexval(ai->first.address) << "\n";
                } else {
                    m << "\t\tA misses binding for: " << hexval(bi->first.address) << "\n";
                }
            }
            if (DebugLogStateMerge) {
                m << "merge failed: different callstacks" << '\n';
            }
            return false;
        }
        if (ai->second != bi->second && !s_ignoredMergeObjects.count(ai->first)) {

            auto &mo = ai->first;
            auto os = ai->second;
            if (DebugLogStateMerge)
                m << "\t\tmutated: " << hexval(mo.address) << " (" << os->getName() << ")\n";
            if (os->isSharedConcrete()) {
                if (DebugLogStateMerge) {
                    m << "merge failed: different shared-concrete objects " << '\n';
                }
                return false;
            }
            mutated.insert(mo);
        }
    }

    // merge stack

    ref<Expr> inA = ConstantExpr::alloc(1, Expr::Bool);
    ref<Expr> inB = ConstantExpr::alloc(1, Expr::Bool);

    for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it) {
        inA = AndExpr::create(inA, *it);
    }

    for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it) {
        inB = AndExpr::create(inB, *it);
    }

    // XXX should we have a preference as to which predicate to use?
    // it seems like it can make a difference, even though logically
    // they must contradict each other and so inA => !inB

    int selectCountStack = 0, selectCountMem = 0;

    auto itA = stack.begin();
    auto itB = b.stack.begin();
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
                selectCountStack += 1;
            }
        }
    }

    if (DebugLogStateMerge) {
        m << "\t\tcreated " << selectCountStack << " select expressions on the stack\n";
    }

    for (auto mo : mutated) {
        auto os = addressSpace.findObject(mo.address);
        auto otherOS = b.addressSpace.findObject(mo.address);
        assert(os && !os->isReadOnly() && "objects mutated but not writable in merging state");
        assert(otherOS);

        if (DebugLogStateMerge) {
            m << "Merging object " << os->getName() << "\n";
        }

        auto wos = addressSpace.getWriteable(os);
        for (unsigned i = 0; i < mo.size; i++) {
            ref<Expr> av = wos->read8(i);
            ref<Expr> bv = otherOS->read8(i);
            if (av != bv) {
                ref<Expr> e = SelectExpr::create(inA, av, bv);
                wos->write(i, e);
                selectCountMem += 1;
            }
        }
    }

    if (DebugLogStateMerge) {
        m << "\t\tcreated " << selectCountMem << " select expressions in memory\n";
    }

    // XXX: Need to roll back the state of the incremental solver to the last
    // common constraint.

    auto constraints = ConstraintManager();
    for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
        constraints.addConstraint(*it);
    constraints.addConstraint(OrExpr::create(inA, inB));
    m_constraints = constraints;

    // XXX: do we need to recompute concolic values?

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
        auto &arr = symbolics[i];
        std::vector<unsigned char> data;
        for (unsigned s = 0; s < arr->getSize(); ++s) {
            ref<Expr> e = concolics->evaluate(arr, s);
            if (!isa<ConstantExpr>(e)) {
                (*klee_warning_stream) << "Failed to evaluate concrete value for " << arr->getName() << "[" << s
                                       << "]: " << e << "\n";
                (*klee_warning_stream) << "  Symbolics (" << symbolics.size() << "):\n";
                for (auto it : symbolics) {
                    (*klee_warning_stream) << "    " << it->getName() << "\n";
                }
                (*klee_warning_stream) << "  Assignments (" << concolics->bindings.size() << "):\n";
                for (auto it : concolics->bindings) {
                    (*klee_warning_stream) << "    " << it.first->getName() << "\n";
                }
                klee_warning_stream->flush();
                pabort("Failed to evaluate concrete value");
            }

            uint8_t val = dyn_cast<ConstantExpr>(e)->getZExtValue();
            data.push_back(val);
        }

        res.push_back(std::make_pair(arr->getName(), data));
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
ref<ConstantExpr> ExecutionState::toConstant(ref<Expr> e, const std::string &reason) {
    e = simplifyExpr(e);
    e = m_constraints.simplifyExpr(e);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e)) {
        return CE;
    }

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

    os << "(reason: " << reason << ") ";

    if (PrintConcretizedExpression) {
        os << " expression " << e;
    }

    os << " to value " << value;

    klee_warning_external(reason.c_str(), "%s", os.str().c_str());

    if (!addConstraint(EqExpr::create(e, value))) {
        abort();
    }

    return value;
}

// This API does not add a constraint
ref<ConstantExpr> ExecutionState::toConstantSilent(ref<Expr> e) {
    ref<Expr> evalResult = concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    return dyn_cast<ConstantExpr>(evalResult);
}

ref<Expr> ExecutionState::toUnique(ref<Expr> &e) {
    e = simplifyExpr(e);
    ref<Expr> result = e;

    if (isa<ConstantExpr>(e)) {
        return result;
    }

    ref<ConstantExpr> value;

    ref<Expr> evalResult = concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    value = dyn_cast<ConstantExpr>(evalResult);

    bool isTrue = false;
    bool success = solver()->mustBeTrue(*this, simplifyExpr(EqExpr::create(e, value)), isTrue);

    if (success && isTrue) {
        result = value;
    }

    return result;
}

bool ExecutionState::solve(const ConstraintManager &mgr, Assignment &assignment) {
    ArrayVec symbObjects;
    for (unsigned i = 0; i < symbolics.size(); ++i) {
        symbObjects.push_back(symbolics[i]);
    }

    std::vector<std::vector<unsigned char>> concreteObjects;
    if (!solver()->getInitialValues(mgr, symbObjects, concreteObjects, queryCost)) {
        return false;
    }

    assignment.clear();
    for (unsigned i = 0; i < symbObjects.size(); ++i) {
        assignment.add(symbObjects[i], concreteObjects[i]);
    }

    return true;
}

bool ExecutionState::addConstraint(const ref<Expr> &constraint, bool recomputeConcolics) {
    auto simplified = simplifyExpr(constraint);
    auto se = dyn_cast<ConstantExpr>(simplified);
    if (se && !se->isTrue()) {
        *klee_warning_stream << "Attempt to add invalid constraint:" << simplified << "\n";
        return false;
    }

    auto evaluated = concolics->evaluate(simplified);
    ConstantExpr *ce = dyn_cast<ConstantExpr>(evaluated);
    if (!ce) {
        *klee_warning_stream << "Constraint does not evaluate to a constant:" << evaluated << "\n";
        return false;
    }

    if (!ce->isTrue()) {
        if (recomputeConcolics) {
            ConstraintManager newConstraints = m_constraints;
            newConstraints.addConstraint(simplified);
            if (!solve(newConstraints, *concolics)) {
                *klee_warning_stream << "Could not compute concolic values for the new constraint\n";
                return false;
            }
        } else {
            *klee_warning_stream << "Attempted to add a constraint that requires recomputing concolic values\n";
            return false;
        }
    }

    // Constraint is good, add it to the actual set
    m_constraints.addConstraint(simplified);

    return true;
}

/// \brief Print query to solve state constraints
/// Will print query in format understandable by kleaver.
///
/// \param os output stream
void ExecutionState::dumpQuery(llvm::raw_ostream &os) const {
    ArrayVec symbObjects;
    for (unsigned i = 0; i < symbolics.size(); ++i) {
        symbObjects.push_back(symbolics[i]);
    }

    auto printer = std::unique_ptr<ExprPPrinter>(ExprPPrinter::create(os));

    Query query(m_constraints, ConstantExpr::alloc(0, Expr::Bool));

    std::vector<ref<Expr>> exprs;
    printer->printQuery(os, query.constraints, query.expr, exprs.begin(), exprs.end(), symbObjects.begin(),
                        symbObjects.end(), true);
    os.flush();
}

std::shared_ptr<TimingSolver> ExecutionState::solver() const {
    return SolverManager::solver(*this);
}

Cell &ExecutionState::getArgumentCell(KFunction *kf, unsigned index) {
    return stack.back().locals[kf->getArgRegister(index)];
}

Cell &ExecutionState::getDestCell(KInstruction *target) {
    return stack.back().locals[target->dest];
}

void ExecutionState::bindLocal(KInstruction *target, ref<Expr> value) {

    getDestCell(target).value = simplifyExpr(value);
}

void ExecutionState::bindArgument(KFunction *kf, unsigned index, ref<Expr> value) {
    getArgumentCell(kf, index).value = simplifyExpr(value);
}

void ExecutionState::stepInstruction() {
    if (DebugPrintInstructions) {
        llvm::errs() << stats::instructions << " ";
        llvm::errs() << *(pc->inst) << "\n";
    }

    ++stats::instructions;
    prevPC = pc;
    ++pc;
}

void ExecutionState::bindObject(const ObjectStatePtr &os, bool isLocal) {
    addressSpace.bindObject(os);

    // Its possible that multiple bindings of the same mo in the state
    // will put multiple copies on this list, but it doesn't really
    // matter because all we use this list for is to unbind the object
    // on function return.
    if (isLocal) {
        stack.back().allocas.push_back(os->getKey());
    }
}
} // namespace klee
