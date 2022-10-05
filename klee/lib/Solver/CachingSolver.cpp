//===-- CachingSolver.cpp - Caching expression solver ---------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <klee/Common.h>
#include "klee/Solver.h"

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/IncompleteSolver.h"
#include "klee/SolverImpl.h"

#include "klee/Stats/SolverStats.h"

#include <unordered_map>

using namespace klee;

class CachingSolver : public SolverImpl {
private:
    ref<Expr> canonicalizeQuery(ref<Expr> originalQuery, bool &negationUsed);

    void cacheInsert(const Query &query, IncompleteSolver::PartialValidity result);

    bool cacheLookup(const Query &query, IncompleteSolver::PartialValidity &result);

    struct CacheEntry {
        CacheEntry(const ConstraintManager &c, ref<Expr> q) : constraints(c), query(q) {
        }

        CacheEntry(const CacheEntry &ce) : constraints(ce.constraints), query(ce.query) {
        }

        ConstraintManager constraints;
        ref<Expr> query;

        bool operator==(const CacheEntry &b) const {
            return constraints == b.constraints && *query.get() == *b.query.get();
        }
    };

    struct CacheEntryHash {
        unsigned operator()(const CacheEntry &ce) const {
            unsigned result = ce.query->hash();

            for (ConstraintManager::const_iterator it = ce.constraints.begin(); it != ce.constraints.end(); ++it)
                result ^= ce.constraints.toExpr((*it))->hash();

            return result;
        }
    };

    typedef std::unordered_map<CacheEntry, IncompleteSolver::PartialValidity, CacheEntryHash> cache_map;

    SolverPtr solver;
    cache_map cache;

private:
    CachingSolver(SolverPtr &s) : solver(s) {
    }

public:
    ~CachingSolver() {
        cache.clear();
    }

    bool computeValidity(const Query &, Validity &result);
    bool computeTruth(const Query &, bool &isValid);
    bool computeValue(const Query &query, ref<Expr> &result) {
        return solver->impl->computeValue(query, result);
    }
    bool computeInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
        return solver->impl->computeInitialValues(query, objects, values, hasSolution);
    }

    static SolverImplPtr create(SolverPtr &s) {
        return SolverImplPtr(new CachingSolver(s));
    }
};

/** @returns the canonical version of the given query.  The reference
    negationUsed is set to true if the original query was negated in
    the canonicalization process. */
ref<Expr> CachingSolver::canonicalizeQuery(ref<Expr> originalQuery, bool &negationUsed) {
    ref<Expr> negatedQuery = Expr::createIsZero(originalQuery);

    // select the "smaller" query to the be canonical representation
    if (originalQuery.compare(negatedQuery) < 0) {
        negationUsed = false;
        return originalQuery;
    } else {
        negationUsed = true;
        return negatedQuery;
    }
}

/** @returns true on a cache hit, false of a cache miss.  Reference
    value result only valid on a cache hit. */
bool CachingSolver::cacheLookup(const Query &query, IncompleteSolver::PartialValidity &result) {
    bool negationUsed;
    ref<Expr> canonicalQuery = canonicalizeQuery(query.expr, negationUsed);

    CacheEntry ce(query.constraints, canonicalQuery);
    cache_map::iterator it = cache.find(ce);

    if (it != cache.end()) {
        result = (negationUsed ? IncompleteSolver::negatePartialValidity(it->second) : it->second);
        return true;
    }

    return false;
}

/// Inserts the given query, result pair into the cache.
void CachingSolver::cacheInsert(const Query &query, IncompleteSolver::PartialValidity result) {
    bool negationUsed;
    ref<Expr> canonicalQuery = canonicalizeQuery(query.expr, negationUsed);

    CacheEntry ce(query.constraints, canonicalQuery);
    IncompleteSolver::PartialValidity cachedResult =
        (negationUsed ? IncompleteSolver::negatePartialValidity(result) : result);

    cache.insert(std::make_pair(ce, cachedResult));
}

bool CachingSolver::computeValidity(const Query &query, Validity &result) {
    IncompleteSolver::PartialValidity cachedResult;
    bool tmp, cacheHit = cacheLookup(query, cachedResult);

    if (cacheHit) {
        ++*stats::queryCacheHits;

        switch (cachedResult) {
            case IncompleteSolver::MustBeTrue:
                result = Validity::True;
                return true;
            case IncompleteSolver::MustBeFalse:
                result = Validity::False;
                return true;
            case IncompleteSolver::TrueOrFalse:
                result = Validity::Unknown;
                return true;
            case IncompleteSolver::MayBeTrue: {
                if (!solver->impl->computeTruth(query, tmp))
                    return false;
                if (tmp) {
                    cacheInsert(query, IncompleteSolver::MustBeTrue);
                    result = Validity::True;
                    return true;
                } else {
                    cacheInsert(query, IncompleteSolver::TrueOrFalse);
                    result = Validity::Unknown;
                    return true;
                }
            }
            case IncompleteSolver::MayBeFalse: {
                if (!solver->impl->computeTruth(query.negateExpr(), tmp))
                    return false;
                if (tmp) {
                    cacheInsert(query, IncompleteSolver::MustBeFalse);
                    result = Validity::False;
                    return true;
                } else {
                    cacheInsert(query, IncompleteSolver::TrueOrFalse);
                    result = Validity::Unknown;
                    return true;
                }
            }
            default:
                pabort("unreachable");
        }
    }

    ++*stats::queryCacheMisses;

    if (!solver->impl->computeValidity(query, result))
        return false;

    switch (result) {
        case Validity::True:
            cachedResult = IncompleteSolver::MustBeTrue;
            break;
        case Validity::False:
            cachedResult = IncompleteSolver::MustBeFalse;
            break;
        default:
            cachedResult = IncompleteSolver::TrueOrFalse;
            break;
    }

    cacheInsert(query, cachedResult);
    return true;
}

bool CachingSolver::computeTruth(const Query &query, bool &isValid) {
    IncompleteSolver::PartialValidity cachedResult;
    bool cacheHit = cacheLookup(query, cachedResult);

    // a cached result of MayBeTrue forces us to check whether
    // a False assignment exists.
    if (cacheHit && cachedResult != IncompleteSolver::MayBeTrue) {
        ++*stats::queryCacheHits;
        isValid = (cachedResult == IncompleteSolver::MustBeTrue);
        return true;
    }

    ++*stats::queryCacheMisses;

    // cache miss: query solver
    if (!solver->impl->computeTruth(query, isValid))
        return false;

    if (isValid) {
        cachedResult = IncompleteSolver::MustBeTrue;
    } else if (cacheHit) {
        // We know a true assignment exists, and query isn't valid, so
        // must be TrueOrFalse.
        assert(cachedResult == IncompleteSolver::MayBeTrue);
        cachedResult = IncompleteSolver::TrueOrFalse;
    } else {
        cachedResult = IncompleteSolver::MayBeFalse;
    }

    cacheInsert(query, cachedResult);
    return true;
}

///

SolverPtr klee::createCachingSolver(SolverPtr &_solver) {
    return Solver::create(CachingSolver::create(_solver));
}
