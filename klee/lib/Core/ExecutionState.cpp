//===-- ExecutionState.cpp ------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/ExecutionState.h"
#include "klee/Stats/CoreStats.h"

#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"

#include "klee/Expr.h"

#include "klee/Memory.h"
#include "klee/util/ExprPPrinter.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
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

// This is set to false in order to avoid the overhead of printing large expressions
cl::opt<bool> PrintConcretizedExpression("print-concretized-expression", cl::desc("Print concretized expression."),
                                         cl::init(false));

/***/

BitfieldSimplifier ExecutionState::s_simplifier;
std::set<ObjectKey, ObjectKeyLTS> ExecutionState::s_ignoredMergeObjects;

ExecutionState::ExecutionState(KFunction *kf)
    : m_addressSpace(this), m_concolics(Assignment::create(true)), forkDisabled(false), llvm(this) {
    llvm.initialize(kf);
}

ExecutionState::~ExecutionState() {

}

ExecutionState *ExecutionState::clone() {
    ExecutionState *state = new ExecutionState(*this);
    state->m_addressSpace.state = state;
    state->llvm.state = state;
    state->m_concolics = Assignment::create(true);
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

    if (!llvm.mergeable(b.llvm)) {
        return false;
    }

    // XXX is it even possible for these to differ? does it matter? probably
    // implies difference in object states?
    if (m_symbolics != b.m_symbolics) {
        if (DebugLogStateMerge) {
            m << "merge failed: different m_symbolics" << '\n';

            for (auto it : m_symbolics) {
                m << it->getName() << "\n";
            }
            m << "\n";
            for (auto it : b.m_symbolics) {
                m << it->getName() << "\n";
            }
        }
        return false;
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
    MemoryMap::iterator ai = m_addressSpace.objects.begin();
    MemoryMap::iterator bi = b.m_addressSpace.objects.begin();
    MemoryMap::iterator ae = m_addressSpace.objects.end();
    MemoryMap::iterator be = b.m_addressSpace.objects.end();
    for (; ai != ae && bi != be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    m << "\t\tB misses binding for: " << hexval(ai->first.address) << "\n";
                } else {
                    m << "\t\tA misses binding for: " << hexval(bi->first.address) << "\n";
                }
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
    if (ai != ae || bi != be) {
        if (DebugLogStateMerge) {
            m << "\t\tmappings differ\n";
        }
        return false;
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

    llvm.merge(b.llvm, inA);

    int selectCountMem = 0;
    for (auto mo : mutated) {
        auto os = m_addressSpace.findObject(mo.address);
        auto otherOS = b.m_addressSpace.findObject(mo.address);
        assert(os && !os->isReadOnly() && "objects mutated but not writable in merging state");
        assert(otherOS);

        if (DebugLogStateMerge) {
            m << "Merging object " << os->getName() << "\n";
        }

        auto wos = m_addressSpace.getWriteable(os);
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

bool ExecutionState::getSymbolicSolution(std::vector<std::pair<std::string, std::vector<unsigned char>>> &res) {
    for (unsigned i = 0; i != m_symbolics.size(); ++i) {
        auto &arr = m_symbolics[i];
        std::vector<unsigned char> data;
        for (unsigned s = 0; s < arr->getSize(); ++s) {
            ref<Expr> e = m_concolics->evaluate(arr, s);
            if (!isa<ConstantExpr>(e)) {
                (*klee_warning_stream) << "Failed to evaluate concrete value for " << arr->getName() << "[" << s
                                       << "]: " << e << "\n";
                (*klee_warning_stream) << "  Symbolics (" << m_symbolics.size() << "):\n";
                for (auto it : m_symbolics) {
                    (*klee_warning_stream) << "    " << it->getName() << "\n";
                }
                (*klee_warning_stream) << "  Assignments (" << m_concolics->bindings.size() << "):\n";
                for (auto it : m_concolics->bindings) {
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

        ref<Expr> originalConcrete = m_concolics->evaluate(e);
        ref<Expr> simplifiedConcrete = m_concolics->evaluate(simplified);
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

    ref<Expr> evalResult = m_concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    value = dyn_cast<ConstantExpr>(evalResult);

    std::string s;
    raw_string_ostream os(s);

    os << "silently concretizing ";

    const auto ki = llvm.prevPC;
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

uint64_t ExecutionState::toConstant(const ref<Expr> &value, const ObjectStateConstPtr &os, size_t offset) {
    std::stringstream ss;
    if (os->isSharedConcrete()) {
        ss << "write to always concrete memory ";
    }

    ss << "name:" << os->getName() << " offset=" << offset;
    auto s = ss.str();
    auto ce = toConstant(value, s.c_str());
    return ce->getZExtValue();
}

// This API does not add a constraint
ref<ConstantExpr> ExecutionState::toConstantSilent(ref<Expr> e) {
    ref<Expr> evalResult = m_concolics->evaluate(e);
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

    ref<Expr> evalResult = m_concolics->evaluate(e);
    assert(isa<ConstantExpr>(evalResult) && "Must be concrete");
    value = dyn_cast<ConstantExpr>(evalResult);

    bool isTrue = false;
    Query q(constraints(), simplifyExpr(EqExpr::create(e, value)));
    bool success = solver()->mustBeTrue(q, isTrue);

    if (success && isTrue) {
        result = value;
    }

    return result;
}

bool ExecutionState::solve(const ConstraintManager &mgr, Assignment &assignment) {
    std::vector<std::vector<unsigned char>> concreteObjects;
    Query q(mgr, ConstantExpr::alloc(0, Expr::Bool));

    if (!solver()->getInitialValues(q, m_symbolics, concreteObjects)) {
        return false;
    }

    assignment.clear();
    for (unsigned i = 0; i < m_symbolics.size(); ++i) {
        assignment.add(m_symbolics[i], concreteObjects[i]);
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

    auto evaluated = m_concolics->evaluate(simplified);
    ConstantExpr *ce = dyn_cast<ConstantExpr>(evaluated);
    if (!ce) {
        *klee_warning_stream << "Constraint does not evaluate to a constant:" << evaluated << "\n";
        return false;
    }

    if (!ce->isTrue()) {
        if (recomputeConcolics) {
            ConstraintManager newConstraints = m_constraints;
            newConstraints.addConstraint(simplified);
            if (!solve(newConstraints, *m_concolics)) {
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
    for (unsigned i = 0; i < m_symbolics.size(); ++i) {
        symbObjects.push_back(m_symbolics[i]);
    }

    auto printer = std::unique_ptr<ExprPPrinter>(ExprPPrinter::create(os));

    Query query(m_constraints, ConstantExpr::alloc(0, Expr::Bool));

    std::vector<ref<Expr>> exprs;
    printer->printQuery(os, query.constraints, query.expr, exprs.begin(), exprs.end(), symbObjects.begin(),
                        symbObjects.end(), true);
    os.flush();
}

SolverPtr ExecutionState::solver() const {
    return m_solver;
}

void ExecutionState::bindLocal(KInstruction *target, ref<Expr> value) {

    llvm.bindLocal(target, simplifyExpr(value));
}

void ExecutionState::bindArgument(KFunction *kf, unsigned index, ref<Expr> value) {
    llvm.bindArgument(kf, index, simplifyExpr(value));
}

ObjectStatePtr ExecutionState::addExternalObject(void *addr, unsigned size, bool isReadOnly, bool isSharedConcrete) {
    auto ret = ObjectState::allocate((uint64_t) addr, size, true);
    bindObject(ret, false);
    ret->setSharedConcrete(isSharedConcrete);
    if (!isSharedConcrete) {
        memcpy(ret->getConcreteBuffer(), addr, size);
    }

    ret->setReadOnly(isReadOnly);

    return ret;
}

void ExecutionState::bindObject(const ObjectStatePtr &os, bool isLocal) {
    m_addressSpace.bindObject(os);

    // Its possible that multiple bindings of the same mo in the state
    // will put multiple copies on this list, but it doesn't really
    // matter because all we use this list for is to unbind the object
    // on function return.
    if (isLocal) {
        llvm.stack.back().allocas.push_back(os->getKey());
    }
}

void ExecutionState::executeAlloc(ref<Expr> size, bool isLocal, KInstruction *target, bool zeroMemory,
                                  const ObjectStatePtr &reallocFrom) {
    size = toUnique(size);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(size)) {
        auto mo = ObjectState::allocate(0, CE->getZExtValue(), false);
        if (!mo) {
            bindLocal(target, ConstantExpr::alloc(0, Context::get().getPointerWidth()));
        } else {
            bindObject(mo, isLocal);
            bindLocal(target, mo->getBaseExpr());

            if (reallocFrom) {
                unsigned count = std::min(reallocFrom->getSize(), mo->getSize());
                for (unsigned i = 0; i < count; i++) {
                    mo->write(i, reallocFrom->read8(i));
                }
                m_addressSpace.unbindObject(reallocFrom->getKey());
            }
        }
    } else {
        pabort("S2E should not cause allocs with symbolic size");
        abort();
    }
}

ref<Expr> ExecutionState::executeMemoryRead(uint64_t concreteAddress, unsigned bytes) {
    auto ret = m_addressSpace.read(concreteAddress, bytes * 8);
    if (!ret) {
        pabort("read failed");
    }
    return ret;
}

void ExecutionState::executeMemoryWrite(uint64_t concreteAddress, const ref<Expr> &value) {
    auto concretizer = [&](const ref<Expr> &value, const ObjectStateConstPtr &os, size_t offset) {
        return toConstant(value, os, offset);
    };

    if (!m_addressSpace.write(concreteAddress, value, concretizer)) {
        pabort("write failed");
    }
}

} // namespace klee
