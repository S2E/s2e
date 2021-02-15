//===-- TimingSolver.h ------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_TIMINGSOLVER_H
#define KLEE_TIMINGSOLVER_H

#include "klee/Expr.h"
#include "klee/Solver.h"

#include <memory>
#include <vector>

namespace klee {
class ExecutionState;
class Solver;

class TimingSolver;
using TimingSolverPtr = std::shared_ptr<TimingSolver>;

/// TimingSolver - A simple class which wraps a solver and handles
/// tracking the statistics that we care about.
class TimingSolver {
public:
    SolverPtr solver;
    bool simplifyExprs;

private:
    /// TimingSolver - Construct a new timing solver.
    ///
    /// \param _simplifyExprs - Whether expressions should be
    /// simplified (via the constraint manager interface) prior to
    /// querying.
    TimingSolver(SolverPtr &_solver, bool _simplifyExprs = true) : solver(_solver), simplifyExprs(_simplifyExprs) {
    }

public:
    void setTimeout(double t) {
    }

    bool evaluate(const ExecutionState &, ref<Expr>, Validity &result);

    bool mustBeTrue(const ExecutionState &, ref<Expr>, bool &result);

    bool mustBeFalse(const ExecutionState &, ref<Expr>, bool &result);

    bool mayBeTrue(const ExecutionState &, ref<Expr>, bool &result);

    bool mayBeFalse(const ExecutionState &, ref<Expr>, bool &result);

    bool getValue(const ExecutionState &, ref<Expr> expr, ref<ConstantExpr> &result);

    bool getInitialValues(const ConstraintManager &constraints, const ArrayVec &objects,
                          std::vector<std::vector<unsigned char>> &result, double &queryCost);
    bool getInitialValues(const ExecutionState &, const ArrayVec &objects,
                          std::vector<std::vector<unsigned char>> &result);

    std::pair<ref<Expr>, ref<Expr>> getRange(const ExecutionState &, ref<Expr> query);

    static TimingSolverPtr create(SolverPtr &_solver, bool _simplifyExprs = true) {
        return TimingSolverPtr(new TimingSolver(_solver, _simplifyExprs));
    }
};
} // namespace klee

#endif
