//===-- TimingSolver.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <chrono>

#include "klee/TimingSolver.h"

#include "klee/Common.h"
#include "klee/Solver.h"

#include "klee/Stats/CoreStats.h"

using namespace llvm;
using namespace std::chrono;

namespace klee {
template <typename Func> static bool measureTime(double &queryCost, Func f) {
    auto t1 = steady_clock::now();

    auto ret = f();

    auto diff = steady_clock::now() - t1;
    *stats::solverTime += duration_cast<microseconds>(diff).count();
    queryCost += duration_cast<duration<double>>(diff).count();
    return ret;
}

bool TimingSolver::computeTruth(const Query &query, bool &isValid) {
    return measureTime(m_queryCost, [&]() -> bool { return m_solver->impl->computeTruth(query, isValid); });
}

bool TimingSolver::computeValidity(const Query &query, Validity &result) {
    return measureTime(m_queryCost, [&]() -> bool { return m_solver->impl->computeValidity(query, result); });
}

bool TimingSolver::computeValue(const Query &query, ref<Expr> &result) {
    return measureTime(m_queryCost, [&]() -> bool { return m_solver->impl->computeValue(query, result); });
}

bool TimingSolver::computeInitialValues(const Query &query, const ArrayVec &objects,
                                        std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    return measureTime(m_queryCost, [&]() -> bool {
        return m_solver->impl->computeInitialValues(query, objects, values, hasSolution);
    });
}

SolverPtr createTimingSolver(SolverPtr &s) {
    return Solver::create(TimingSolver::create(s));
}
} // namespace klee