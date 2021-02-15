//===-- IndependentSolver.cpp ---------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Solver.h"

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/SolverImpl.h"

#include "klee/util/ExprUtil.h"

#include <iostream>
#include <map>
#include <ostream>
#include <vector>

using namespace klee;
using namespace llvm;

template <class T> class DenseSet {
    typedef std::set<T> set_ty;
    set_ty s;

public:
    DenseSet() {
    }

    void add(T x) {
        s.insert(x);
    }
    void add(T start, T end) {
        for (; start < end; start++)
            s.insert(start);
    }

    // returns true iff set is changed by addition
    bool add(const DenseSet &b) {
        bool modified = false;
        for (typename set_ty::const_iterator it = b.s.begin(), ie = b.s.end(); it != ie; ++it) {
            if (modified || !s.count(*it)) {
                modified = true;
                s.insert(*it);
            }
        }
        return modified;
    }

    bool intersects(const DenseSet &b) {
        for (typename set_ty::iterator it = s.begin(), ie = s.end(); it != ie; ++it)
            if (b.s.count(*it))
                return true;
        return false;
    }

    void print(llvm::raw_ostream &os) const {
        bool first = true;
        os << "{";
        for (typename set_ty::iterator it = s.begin(), ie = s.end(); it != ie; ++it) {
            if (first) {
                first = false;
            } else {
                os << ",";
            }
            os << *it;
        }
        os << "}";
    }
};

template <class T> inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const DenseSet<T> &dis) {
    dis.print(os);
    return os;
}

class IndependentElementSet {
    typedef std::map<ArrayPtr, DenseSet<unsigned>, ArrayLt> elements_ty;
    elements_ty elements;
    std::unordered_set<ArrayPtr, ArrayHash> wholeObjects;

public:
    IndependentElementSet() {
    }
    IndependentElementSet(ref<Expr> e) {
        std::vector<ref<ReadExpr>> reads;
        findReads(e, /* visitUpdates= */ true, reads);
        for (unsigned i = 0; i != reads.size(); ++i) {
            ReadExpr *re = reads[i].get();
            auto &array = re->getUpdates()->getRoot();

            // Reads of a constant array don't alias.
            if (re->getUpdates()->getRoot()->isConstantArray() && !re->getUpdates()->getHead())
                continue;

            if (!wholeObjects.count(array)) {
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(re->getIndex())) {
                    DenseSet<unsigned> &dis = elements[array];
                    dis.add((unsigned) CE->getZExtValue(32));
                } else {
                    elements_ty::iterator it2 = elements.find(array);
                    if (it2 != elements.end())
                        elements.erase(it2);
                    wholeObjects.insert(array);
                }
            }
        }
    }
    IndependentElementSet(const IndependentElementSet &ies) : elements(ies.elements), wholeObjects(ies.wholeObjects) {
    }

    IndependentElementSet &operator=(const IndependentElementSet &ies) {
        elements = ies.elements;
        wholeObjects = ies.wholeObjects;
        return *this;
    }

    void print(llvm::raw_ostream &os) const {
        os << "{";
        bool first = true;
        for (auto array : wholeObjects) {

            if (first) {
                first = false;
            } else {
                os << ", ";
            }

            os << "MO" << array->getName();
        }
        for (auto it : elements) {
            auto array = it.first;
            const DenseSet<unsigned> &dis = it.second;

            if (first) {
                first = false;
            } else {
                os << ", ";
            }

            os << "MO" << array->getName() << " : " << dis;
        }
        os << "}";
    }

    // more efficient when this is the smaller set
    bool intersects(const IndependentElementSet &b) {
        for (auto array : wholeObjects) {
            if (b.wholeObjects.count(array) || b.elements.find(array) != b.elements.end())
                return true;
        }
        for (auto it : elements) {
            auto &array = it.first;
            if (b.wholeObjects.count(array))
                return true;

            auto it2 = b.elements.find(array);
            if (it2 != b.elements.end()) {
                if (it.second.intersects(it2->second))
                    return true;
            }
        }
        return false;
    }

    // returns true iff set is changed by addition
    bool add(const IndependentElementSet &b) {
        bool modified = false;
        for (auto array : b.wholeObjects) {
            elements_ty::iterator it2 = elements.find(array);
            if (it2 != elements.end()) {
                modified = true;
                elements.erase(it2);
                wholeObjects.insert(array);
            } else {
                if (!wholeObjects.count(array)) {
                    modified = true;
                    wholeObjects.insert(array);
                }
            }
        }
        for (auto it : elements) {
            auto &array = it.first;
            if (!wholeObjects.count(array)) {
                auto it2 = elements.find(array);
                if (it2 == elements.end()) {
                    modified = true;
                    elements.insert(it);
                } else {
                    if (it2->second.add(it.second))
                        modified = true;
                }
            }
        }
        return modified;
    }
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const IndependentElementSet &ies) {
    ies.print(os);
    return os;
}

static IndependentElementSet getIndependentConstraints(const Query &query, std::vector<ref<Expr>> &result) {
    IndependentElementSet eltsClosure(query.expr);
    std::vector<std::pair<ref<Expr>, IndependentElementSet>> worklist;

    for (ConstraintManager::const_iterator it = query.constraints.begin(), ie = query.constraints.end(); it != ie;
         ++it) {
        ref<Expr> e = query.constraints.toExpr(*it);
        worklist.push_back(std::make_pair(e, IndependentElementSet(e)));
    }

    // XXX This should be more efficient (in terms of low level copy stuff).
    bool done = false;
    do {
        done = true;
        std::vector<std::pair<ref<Expr>, IndependentElementSet>> newWorklist;
        for (std::vector<std::pair<ref<Expr>, IndependentElementSet>>::iterator it = worklist.begin(),
                                                                                ie = worklist.end();
             it != ie; ++it) {
            if (it->second.intersects(eltsClosure)) {
                if (eltsClosure.add(it->second))
                    done = false;
                result.push_back(it->first);
            } else {
                newWorklist.push_back(*it);
            }
        }
        worklist.swap(newWorklist);
    } while (!done);

    if (0) {
        std::set<ref<Expr>> reqset(result.begin(), result.end());
        llvm::errs() << "--\n";
        llvm::errs() << "Q: " << query.expr << "\n";
        llvm::errs() << "\telts: " << IndependentElementSet(query.expr) << "\n";
        int i = 0;
        for (ConstraintManager::const_iterator it = query.constraints.begin(), ie = query.constraints.end(); it != ie;
             ++it) {
            ref<Expr> e = query.constraints.toExpr(*it);
            llvm::errs() << "C" << i++ << ": " << e;
            llvm::errs() << " " << (reqset.count(e) ? "(required)" : "(independent)") << "\n";
            llvm::errs() << "\telts: " << IndependentElementSet(e) << "\n";
        }
        llvm::errs() << "elts closure: " << eltsClosure << "\n";
    }

    return eltsClosure;
}

class IndependentSolver : public SolverImpl {
private:
    SolverPtr solver;

    IndependentSolver(SolverPtr _solver) : solver(_solver) {
    }

public:
    ~IndependentSolver() {
    }

    bool computeTruth(const Query &, bool &isValid);
    bool computeValidity(const Query &, Validity &result);
    bool computeValue(const Query &, ref<Expr> &result);
    bool computeInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
        return solver->impl->computeInitialValues(query, objects, values, hasSolution);
    }

    static SolverImplPtr create(SolverPtr &s) {
        return SolverImplPtr(new IndependentSolver(s));
    }
};

bool IndependentSolver::computeValidity(const Query &query, Validity &result) {
    std::vector<ref<Expr>> required;
    IndependentElementSet eltsClosure = getIndependentConstraints(query, required);
    ConstraintManager tmp(required);
    return solver->impl->computeValidity(Query(tmp, query.expr), result);
}

bool IndependentSolver::computeTruth(const Query &query, bool &isValid) {
    std::vector<ref<Expr>> required;
    IndependentElementSet eltsClosure = getIndependentConstraints(query, required);
    ConstraintManager tmp(required);
    return solver->impl->computeTruth(Query(tmp, query.expr), isValid);
}

bool IndependentSolver::computeValue(const Query &query, ref<Expr> &result) {
    std::vector<ref<Expr>> required;
    IndependentElementSet eltsClosure = getIndependentConstraints(query, required);
    ConstraintManager tmp(required);
    return solver->impl->computeValue(Query(tmp, query.expr), result);
}

SolverPtr klee::createIndependentSolver(SolverPtr &s) {
    return Solver::create(IndependentSolver::create(s));
}

void klee::getIndependentConstraintsForQuery(const Query &query, std::vector<ref<Expr>> &required) {
    IndependentElementSet eltsClosure = getIndependentConstraints(query, required);
}
