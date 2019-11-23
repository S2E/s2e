//===-- Solver.cpp --------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Solver.h"
#include <klee/Common.h>
#include "klee/SolverImpl.h"

#include "klee/SolverStats.h"

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/Support/Timer.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprTemplates.h"

#include <cassert>
#include <cstdio>
#include <map>
#include <vector>

using namespace klee;

/***/

const char *Solver::validity_to_str(Validity v) {
    switch (v) {
        default:
            return "Unknown";
        case True:
            return "True";
        case False:
            return "False";
    }
}

Solver::~Solver() {
    delete impl;
}

SolverImpl::~SolverImpl() {
}

bool Solver::evaluate(const Query &query, Validity &result) {
    assert(query.expr->getWidth() == Expr::Bool && "Invalid expression type!");

    // Maintain invariants implementations expect.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(query.expr)) {
        result = CE->isTrue() ? True : False;
        return true;
    }

    return impl->computeValidity(query, result);
}

bool SolverImpl::computeValidity(const Query &query, Solver::Validity &result) {
    bool isTrue, isFalse;
    if (!computeTruth(query, isTrue))
        return false;
    if (isTrue) {
        result = Solver::True;
    } else {
        if (!computeTruth(query.negateExpr(), isFalse))
            return false;
        result = isFalse ? Solver::False : Solver::Unknown;
    }
    return true;
}

bool Solver::mustBeTrue(const Query &query, bool &result) {
    assert(query.expr->getWidth() == Expr::Bool && "Invalid expression type!");

    // Maintain invariants implementations expect.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(query.expr)) {
        result = CE->isTrue() ? true : false;
        return true;
    }

    return impl->computeTruth(query, result);
}

bool Solver::mustBeFalse(const Query &query, bool &result) {
    return mustBeTrue(query.negateExpr(), result);
}

bool Solver::mayBeTrue(const Query &query, bool &result) {
    bool res;
    if (!mustBeFalse(query, res))
        return false;
    result = !res;
    return true;
}

bool Solver::mayBeFalse(const Query &query, bool &result) {
    bool res;
    if (!mustBeTrue(query, res))
        return false;
    result = !res;
    return true;
}

bool Solver::getValue(const Query &query, ref<ConstantExpr> &result) {
    // Maintain invariants implementation expect.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(query.expr)) {
        result = CE;
        return true;
    }

    // FIXME: Push ConstantExpr requirement down.
    ref<Expr> tmp;
    if (!impl->computeValue(query, tmp))
        return false;

    result = cast<ConstantExpr>(tmp);
    return true;
}

bool Solver::getInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values) {
    bool hasSolution;
    bool success = impl->computeInitialValues(query, objects, values, hasSolution);
    // FIXME: Propogate this out.
    if (!hasSolution)
        return false;

    return success;
}

void Solver::getRanges(const ConstraintManager &constraints, const ArrayVec &symbObjects, ref<Expr> e, ref<Expr> start,
                       ref<Expr> end, std::vector<Range> &ranges) {
    ConstraintManager tmpConstraints = constraints;
    tmpConstraints.addConstraint(E_AND(E_GE(e, start), E_LT(e, end)));

    std::vector<uint64_t> values;

    // FIXME: this can be made faster with a binary search
    while (true) {
        std::vector<std::vector<unsigned char>> concreteObjects;
        if (!getInitialValues(Query(tmpConstraints, ConstantExpr::create(0, Expr::Bool)), symbObjects,
                              concreteObjects)) {
            break;
        }

        Assignment newConcolics;
        for (unsigned i = 0; i < symbObjects.size(); ++i) {
            newConcolics.add(symbObjects[i], concreteObjects[i]);
        }

        ref<Expr> value = newConcolics.evaluate(e);
        if (value.isNull()) {
            break;
        }
        values.push_back(dyn_cast<ConstantExpr>(value)->getZExtValue());
        tmpConstraints.addConstraint(E_NEQ(e, value));
    }
    std::sort(values.begin(), values.end());

    // Merge ranges from values
    uint64_t base = *values.begin();
    uint64_t size = 0;
    for (auto it = values.begin(); it != values.end(); ++it) {
        if ((it != values.begin() && *it != (base + size + 1))) {
            ranges.push_back(Range(base, base + size));
            size = 0;
            base = *it;
        } else {
            size += 1;
        }
    }
    if (size != 0) {
        ranges.push_back(Range(base, base + size));
    }
}

std::pair<ref<Expr>, ref<Expr>> Solver::getRange(const Query &query) {
    ref<Expr> e = query.expr;
    Expr::Width width = e->getWidth();
    uint64_t min, max;

    if (width == 1) {
        Solver::Validity result;
        if (!evaluate(query, result))
            pabort("computeValidity failed");
        switch (result) {
            case Solver::True:
                min = max = 1;
                break;
            case Solver::False:
                min = max = 0;
                break;
            default:
                min = 0, max = 1;
                break;
        }
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e)) {
        min = max = CE->getZExtValue();
    } else {
        // binary search for # of useful bits
        uint64_t lo = 0, hi = width, mid, bits = 0;
        while (lo < hi) {
            mid = lo + (hi - lo) / 2;
            bool res;
            bool success =
                mustBeTrue(query.withExpr(EqExpr::create(LShrExpr::create(e, ConstantExpr::create(mid, width)),
                                                         ConstantExpr::create(0, width))),
                           res);

            assert(success && "FIXME: Unhandled solver failure");
            (void) success;

            if (res) {
                hi = mid;
            } else {
                lo = mid + 1;
            }

            bits = lo;
        }

        // could binary search for training zeros and offset
        // min max but unlikely to be very useful

        // check common case
        bool res = false;
        bool success = mayBeTrue(query.withExpr(EqExpr::create(e, ConstantExpr::create(0, width))), res);

        assert(success && "FIXME: Unhandled solver failure");
        (void) success;

        if (res) {
            min = 0;
        } else {
            // binary search for min
            lo = 0, hi = bits64::maxValueOfNBits(bits);
            while (lo < hi) {
                mid = lo + (hi - lo) / 2;
                bool res = false;
                bool success = mayBeTrue(query.withExpr(UleExpr::create(e, ConstantExpr::create(mid, width))), res);

                assert(success && "FIXME: Unhandled solver failure");
                (void) success;

                if (res) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }

            min = lo;
        }

        // binary search for max
        lo = min, hi = bits64::maxValueOfNBits(bits);
        while (lo < hi) {
            mid = lo + (hi - lo) / 2;
            bool res;
            bool success = mustBeTrue(query.withExpr(UleExpr::create(e, ConstantExpr::create(mid, width))), res);

            assert(success && "FIXME: Unhandled solver failure");
            (void) success;

            if (res) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }

        max = lo;
    }

    return std::make_pair(ConstantExpr::create(min, width), ConstantExpr::create(max, width));
}

/***/

class ValidatingSolver : public SolverImpl {
private:
    Solver *solver, *oracle;

public:
    ValidatingSolver(Solver *_solver, Solver *_oracle) : solver(_solver), oracle(_oracle) {
    }
    ~ValidatingSolver() {
        delete solver;
    }

    bool computeValidity(const Query &, Solver::Validity &result);
    bool computeTruth(const Query &, bool &isValid);
    bool computeValue(const Query &, ref<Expr> &result);
    bool computeInitialValues(const Query &, const ArrayVec &objects, std::vector<std::vector<unsigned char>> &values,
                              bool &hasSolution);
};

bool ValidatingSolver::computeTruth(const Query &query, bool &isValid) {
#define VOTING_SOLVER
#define VOTE_COUNT 3
#if defined(VOTING_SOLVER)
    bool results[VOTE_COUNT];
    unsigned trueCount = 0, falseCount = 0;

    for (unsigned i = 0; i < VOTE_COUNT; ++i) {
        bool res1, res2;
        if (!oracle->impl->computeTruth(query, res1))
            return false;

        if (!solver->impl->computeTruth(query, res2))
            return false;

        if (res1 == res2)
            results[i] = res1;
        else
            results[i] = rand() & 1 ? res1 : res2;

        if (results[i])
            ++trueCount;
        else
            ++falseCount;
    }

    if (trueCount > falseCount) {
        isValid = true;
    } else {
        isValid = false;
    }
    return true;
#else
    bool answer;

    if (!solver->impl->computeTruth(query, isValid))
        return false;
    if (!oracle->impl->computeTruth(query, answer))
        return false;

    if (isValid != answer)
        pabort("invalid solver result (computeTruth)");

    return true;
#endif
}

bool ValidatingSolver::computeValidity(const Query &query, Solver::Validity &result) {
#if defined(VOTING_SOLVER)
    Solver::Validity results[VOTE_COUNT];
    unsigned trueCount = 0, falseCount = 0, unknownCount = 0;
    for (unsigned i = 0; i < VOTE_COUNT; ++i) {
        Solver::Validity res1, res2;
        if (!solver->impl->computeValidity(query, res1))
            return false;

        if (!oracle->impl->computeValidity(query, res2))
            return false;

        if (res1 == res2)
            results[i] = res1;
        else
            results[i] = res1;

        switch (results[i]) {
            case Solver::True:
                ++trueCount;
                break;
            case Solver::False:
                ++falseCount;
                break;
            case Solver::Unknown:
                ++unknownCount;
                break;
            default:
                abort();
        }
    }
    if (trueCount > falseCount && falseCount >= unknownCount)
        result = Solver::True;
    else if (trueCount > unknownCount && unknownCount >= falseCount)
        result = Solver::True;
    else if (falseCount > trueCount && trueCount >= unknownCount)
        result = Solver::False;
    else if (falseCount > unknownCount && unknownCount >= trueCount)
        result = Solver::False;
    else if (unknownCount > falseCount && falseCount >= trueCount)
        result = Solver::Unknown;
    else if (unknownCount > trueCount && trueCount >= falseCount)
        result = Solver::Unknown;
    else
        abort();
    return true;
#else
    Solver::Validity answer;

    if (!solver->impl->computeValidity(query, result))
        return false;
    if (!oracle->impl->computeValidity(query, answer))
        return false;

    if (result != answer)
        pabort("invalid solver result (computeValidity)");

    return true;
#endif
}

bool ValidatingSolver::computeValue(const Query &query, ref<Expr> &result) {
    bool answer;

    if (!solver->impl->computeValue(query, result))
        return false;
    // We don't want to compare, but just make sure this is a legal
    // solution.
    if (!oracle->impl->computeTruth(query.withExpr(NeExpr::create(query.expr, result)), answer))
        return false;

    if (answer)
        pabort("invalid solver result (computeValue)");

    return true;
}

bool ValidatingSolver::computeInitialValues(const Query &query, const ArrayVec &objects,
                                            std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    bool answer;

    if (!solver->impl->computeInitialValues(query, objects, values, hasSolution))
        return false;

    if (hasSolution) {
        // Assert the bindings as constraints, and verify that the
        // conjunction of the actual constraints is satisfiable.
        std::vector<ref<Expr>> bindings;
        for (unsigned i = 0; i != values.size(); ++i) {
            auto &array = objects[i];
            for (unsigned j = 0; j < array->getSize(); j++) {
                unsigned char value = values[i][j];
                bindings.push_back(
                    EqExpr::create(ReadExpr::create(UpdateList::create(array, 0), ConstantExpr::alloc(j, Expr::Int32)),
                                   ConstantExpr::alloc(value, Expr::Int8)));
            }
        }
        ConstraintManager tmp(bindings);
        ref<Expr> constraints = Expr::createIsZero(query.expr);
        for (ConstraintManager::const_iterator it = query.constraints.begin(), ie = query.constraints.end(); it != ie;
             ++it)
            constraints = AndExpr::create(constraints, query.constraints.toExpr(*it));

        if (!oracle->impl->computeTruth(Query(tmp, constraints), answer))
            return false;
        if (!answer)
            pabort("invalid solver result (computeInitialValues)");
    } else {
        if (!oracle->impl->computeTruth(query, answer))
            return false;
        if (!answer)
            pabort("invalid solver result (computeInitialValues)");
    }

    return true;
}

Solver *klee::createValidatingSolver(Solver *s, Solver *oracle) {
    return new Solver(new ValidatingSolver(s, oracle));
}

/***/

class DummySolverImpl : public SolverImpl {
public:
    DummySolverImpl() {
    }

    bool computeValidity(const Query &, Solver::Validity &result) {
        ++stats::queries;
        // FIXME: We should have stats::queriesFail;
        return false;
    }
    bool computeTruth(const Query &, bool &isValid) {
        ++stats::queries;
        // FIXME: We should have stats::queriesFail;
        return false;
    }
    bool computeValue(const Query &, ref<Expr> &result) {
        ++stats::queries;
        ++stats::queryCounterexamples;
        return false;
    }
    bool computeInitialValues(const Query &, const ArrayVec &objects, std::vector<std::vector<unsigned char>> &values,
                              bool &hasSolution) {
        ++stats::queries;
        ++stats::queryCounterexamples;
        return false;
    }
};

Solver *klee::createDummySolver() {
    return new Solver(new DummySolverImpl());
}
