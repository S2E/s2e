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

class TimingSolver : public SolverImpl {
private:
    SolverPtr m_solver;

    TimingSolver(SolverPtr _solver) : m_solver(_solver) {
    }

    double m_queryCost = 0.0;

public:
    ~TimingSolver() {
    }

    bool computeTruth(const Query &, bool &isValid);
    bool computeValidity(const Query &, Validity &result);
    bool computeValue(const Query &, ref<Expr> &result);
    bool computeInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution);

    static SolverImplPtr create(SolverPtr &s) {
        return SolverImplPtr(new TimingSolver(s));
    }

    double getTotalQueryCost() const {
        return m_queryCost;
    }
};

} // namespace klee

#endif
