//===-- CexCachingSolver.cpp ----------------------------------------------===//
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
#include "klee/Internal/ADT/MapOfSets.h"
#include "klee/SolverImpl.h"
#include "klee/Stats/TimerStatIncrementer.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprUtil.h"
#include "klee/util/ExprVisitor.h"

#include "klee/Stats/SolverStats.h"

#include "llvm/Support/CommandLine.h"

using namespace klee;
using namespace llvm;

namespace {
cl::opt<bool> DebugCexCacheCheckBinding("debug-cex-cache-check-binding");

cl::opt<bool> CexCacheTryAll("cex-cache-try-all",
                             cl::desc("try substituting all counterexamples before asking the solver"),
                             cl::init(false));

cl::opt<bool> CexCacheExperimental("cex-cache-exp", cl::init(false));
} // namespace

///

typedef std::set<ref<Expr>> KeyType;

struct AssignmentLessThan {
    bool operator()(const AssignmentPtr &a, const AssignmentPtr &b) const {
        return a->bindings < b->bindings;
    }
};

class CexCachingSolver : public SolverImpl {
    typedef std::set<AssignmentPtr, AssignmentLessThan> assignmentsTable_ty;

    SolverPtr solver;

    MapOfSets<ref<Expr>, AssignmentPtr> cache;
    // memo table
    assignmentsTable_ty assignmentsTable;

    bool searchForAssignment(KeyType &key, AssignmentPtr &result);

    bool lookupAssignment(const Query &query, KeyType &key, AssignmentPtr &result);

    bool lookupAssignment(const Query &query, AssignmentPtr &result) {
        KeyType key;
        return lookupAssignment(query, key, result);
    }

    bool getAssignment(const Query &query, AssignmentPtr &result);

    CexCachingSolver(SolverPtr &_solver) : solver(_solver) {
    }

public:
    ~CexCachingSolver();

    bool computeTruth(const Query &, bool &isValid);
    bool computeValidity(const Query &, Validity &result);
    bool computeValue(const Query &, ref<Expr> &result);
    bool computeInitialValues(const Query &, const ArrayVec &objects, std::vector<std::vector<unsigned char>> &values,
                              bool &hasSolution);

    static SolverImplPtr create(SolverPtr &solver) {
        return SolverImplPtr(new CexCachingSolver(solver));
    }
};

///

struct NullAssignment {
    bool operator()(AssignmentPtr &a) const {
        return !a;
    }
};

struct NonNullAssignment {
    bool operator()(AssignmentPtr &a) const {
        return a != 0;
    }
};

struct NullOrSatisfyingAssignment {
    KeyType &key;

    NullOrSatisfyingAssignment(KeyType &_key) : key(_key) {
    }

    bool operator()(AssignmentPtr &a) const {
        return !a || a->satisfies(key.begin(), key.end());
    }
};

/// searchForAssignment - Look for a cached solution for a query.
///
/// \param key - The query to look up.
/// \param result [out] - The cached result, if the lookup is succesful. This is
/// either a satisfying assignment (for a satisfiable query), or 0 (for an
/// unsatisfiable query).
/// \return - True if a cached result was found.
bool CexCachingSolver::searchForAssignment(KeyType &key, AssignmentPtr &result) {
    AssignmentPtr *lookup = cache.lookup(key);
    if (lookup) {
        result = *lookup;
        return true;
    }

    if (CexCacheTryAll) {
        // Look for a satisfying assignment for a superset, which is trivially an
        // assignment for any subset.
        AssignmentPtr *lookup = cache.findSuperset(key, NonNullAssignment());

        // Otherwise, look for a subset which is unsatisfiable, see below.
        if (!lookup) {
            lookup = cache.findSubset(key, NullAssignment());
        }

        // If either lookup succeeded, then we have a cached solution.
        if (lookup) {
            result = *lookup;
            return true;
        }

        // Otherwise, iterate through the set of current assignments to see if one
        // of them satisfies the query.
        for (assignmentsTable_ty::iterator it = assignmentsTable.begin(), ie = assignmentsTable.end(); it != ie; ++it) {
            AssignmentPtr a = *it;
            if (a->satisfies(key.begin(), key.end())) {
                result = a;
                return true;
            }
        }
    } else {
        // FIXME: Which order? one is sure to be better.

        // Look for a satisfying assignment for a superset, which is trivially an
        // assignment for any subset.
        AssignmentPtr *lookup = cache.findSuperset(key, NonNullAssignment());

        // Otherwise, look for a subset which is unsatisfiable -- if the subset is
        // unsatisfiable then no additional constraints can produce a valid
        // assignment. While searching subsets, we also explicitly the solutions for
        // satisfiable subsets to see if they solve the current query and return
        // them if so. This is cheap and frequently succeeds.
        if (!lookup) {
            lookup = cache.findSubset(key, NullOrSatisfyingAssignment(key));
        }

        // If either lookup succeeded, then we have a cached solution.
        if (lookup) {
            result = *lookup;
            return true;
        }
    }

    return false;
}

/// lookupAssignment - Lookup a cached result for the given \arg query.
///
/// \param query - The query to lookup.
/// \param key [out] - On return, the key constructed for the query.
/// \param result [out] - The cached result, if the lookup is succesful. This is
/// either a satisfying assignment (for a satisfiable query), or 0 (for an
/// unsatisfiable query).
/// \return True if a cached result was found.
bool CexCachingSolver::lookupAssignment(const Query &query, KeyType &key, AssignmentPtr &result) {
    key = query.constraints.getConstraintSet();
    ref<Expr> neg = Expr::createIsZero(query.expr);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(neg)) {
        if (CE->isFalse()) {
            result = nullptr;
            return true;
        }
    } else {
        key.insert(neg);
    }

    return searchForAssignment(key, result);
}

bool CexCachingSolver::getAssignment(const Query &query, AssignmentPtr &result) {
    KeyType key;
    if (lookupAssignment(query, key, result)) {
        return true;
    }

    ArrayVec objects;
    findSymbolicObjects(key.begin(), key.end(), objects);

    std::vector<std::vector<unsigned char>> values;
    bool hasSolution;
    if (!solver->impl->computeInitialValues(query, objects, values, hasSolution)) {
        return false;
    }

    AssignmentPtr binding;
    if (hasSolution) {
        binding = Assignment::create(objects, values);

        // Memoize the result.
        auto res = assignmentsTable.insert(binding);
        if (!res.second) {
            binding = *res.first;
        }

        if (DebugCexCacheCheckBinding) {
            assert(binding->satisfies(key.begin(), key.end()));
        }
    } else {
        binding = nullptr;
        // return false;
    }

    result = binding;
    cache.insert(key, binding);

    return true;
}

///

CexCachingSolver::~CexCachingSolver() {
    cache.clear();
}

bool CexCachingSolver::computeValidity(const Query &query, Validity &result) {
    klee::stats::TimerStatIncrementer t(klee::stats::cexCacheTime);
    AssignmentPtr a;
    if (!getAssignment(query.withFalse(), a)) {
        return false;
    }
    assert(a && "computeValidity() must have assignment");
    ref<Expr> q = a->evaluate(query.expr);
    assert(isa<ConstantExpr>(q) && "assignment evaluation did not result in constant");

    if (cast<ConstantExpr>(q)->isTrue()) {
        if (!getAssignment(query, a))
            return false;
        result = !a ? Validity::True : Validity::Unknown;
    } else {
        if (!getAssignment(query.negateExpr(), a))
            return false;
        result = !a ? Validity::False : Validity::Unknown;
    }

    return true;
}

bool CexCachingSolver::computeTruth(const Query &query, bool &isValid) {
    klee::stats::TimerStatIncrementer t(stats::cexCacheTime);

    // There is a small amount of redundancy here. We only need to know
    // truth and do not really need to compute an assignment. This means
    // that we could check the cache to see if we already know that
    // state ^ query has no assignment. In that case, by the validity of
    // state, we know that state ^ !query must have an assignment, and
    // so query cannot be true (valid). This does get hits, but doesn't
    // really seem to be worth the overhead.

    if (CexCacheExperimental) {
        AssignmentPtr a;
        if (lookupAssignment(query.negateExpr(), a) && !a) {
            return false;
        }
    }

    AssignmentPtr a;
    if (!getAssignment(query, a)) {
        return false;
    }

    isValid = !a;

    return true;
}

bool CexCachingSolver::computeValue(const Query &query, ref<Expr> &result) {
    klee::stats::TimerStatIncrementer t(stats::cexCacheTime);

    AssignmentPtr a;
    if (!getAssignment(query.withFalse(), a)) {
        return false;
    }
    assert(a && "computeValue() must have assignment");

    result = a->evaluate(query.expr);
    assert(isa<ConstantExpr>(result) && "assignment evaluation did not result in constant");
    return true;
}

bool CexCachingSolver::computeInitialValues(const Query &query, const ArrayVec &objects,
                                            std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    klee::stats::TimerStatIncrementer t(stats::cexCacheTime);
    AssignmentPtr a;
    if (!getAssignment(query, a)) {
        return false;
    }
    hasSolution = !!a;

    if (!a) {
        return true;
    }

    // FIXME: We should use smarter assignment for result so we don't
    // need redundant copy.
    values = std::vector<std::vector<unsigned char>>(objects.size());
    for (unsigned i = 0; i < objects.size(); ++i) {
        auto &os = objects[i];
        Assignment::bindings_ty::iterator it = a->bindings.find(os);

        if (it == a->bindings.end()) {
            values[i] = std::vector<unsigned char>(os->getSize(), 0);
        } else {
            values[i] = it->second;
        }
    }

    return true;
}

///

SolverPtr klee::createCexCachingSolver(SolverPtr &_solver) {
    return Solver::create(CexCachingSolver::create(_solver));
}
