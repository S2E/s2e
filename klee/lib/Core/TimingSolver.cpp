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
#include "klee/ExecutionState.h"
#include "klee/Solver.h"
#include "klee/Statistics.h"

#include "klee/CoreStats.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Process.h"

using namespace klee;
using namespace llvm;

using namespace std::chrono;

namespace {
llvm::cl::opt<bool> EnableTimingLog("enable-timeingsolver-timing", llvm::cl::desc("TimeingSolver: measure query time"),
                                    llvm::cl::init(false));
}

/***/

template <typename Func> static bool measureTime(double &queryCost, Func f) {
    auto t1 = steady_clock::now();

    auto ret = f();

    auto diff = steady_clock::now() - t1;
    stats::solverTime += duration_cast<microseconds>(diff).count();
    queryCost += duration_cast<duration<double>>(diff).count();
    return ret;
}

bool TimingSolver::evaluate(const ExecutionState &state, ref<Expr> expr, Solver::Validity &result) {

    // Fast path, to avoid timer and OS overhead.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        result = CE->isTrue() ? Solver::True : Solver::False;
        return true;
    }

    if (simplifyExprs)
        expr = state.constraints().simplifyExpr(expr);

    bool success;

    if (EnableTimingLog) {
        success = measureTime(state.queryCost,
                              [&]() -> bool { return solver->evaluate(Query(state.constraints(), expr), result); });
    } else {
        success = solver->evaluate(Query(state.constraints(), expr), result);
    }

    return success;
}

bool TimingSolver::mustBeTrue(const ExecutionState &state, ref<Expr> expr, bool &result) {
    // Fast path, to avoid timer and OS overhead.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        result = CE->isTrue() ? true : false;
        return true;
    }

    if (simplifyExprs)
        expr = state.constraints().simplifyExpr(expr);

    bool success;

    if (EnableTimingLog) {
        success = measureTime(state.queryCost,
                              [&]() -> bool { return solver->mustBeTrue(Query(state.constraints(), expr), result); });
    } else {
        success = solver->mustBeTrue(Query(state.constraints(), expr), result);
    }

    return success;
}

bool TimingSolver::mustBeFalse(const ExecutionState &state, ref<Expr> expr, bool &result) {
    return mustBeTrue(state, Expr::createIsZero(expr), result);
}

bool TimingSolver::mayBeTrue(const ExecutionState &state, ref<Expr> expr, bool &result) {
    bool res;
    if (!mustBeFalse(state, expr, res))
        return false;
    result = !res;
    return true;
}

bool TimingSolver::mayBeFalse(const ExecutionState &state, ref<Expr> expr, bool &result) {
    bool res;
    if (!mustBeTrue(state, expr, res))
        return false;
    result = !res;
    return true;
}

bool TimingSolver::getValue(const ExecutionState &state, ref<Expr> expr, ref<ConstantExpr> &result) {

    // Fast path, to avoid timer and OS overhead.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        result = CE;
        return true;
    }

    if (simplifyExprs)
        expr = state.constraints().simplifyExpr(expr);

    bool success;

    if (EnableTimingLog) {
        success = measureTime(state.queryCost,
                              [&]() -> bool { return solver->getValue(Query(state.constraints(), expr), result); });
    } else {
        success = solver->getValue(Query(state.constraints(), expr), result);
    }

    return success;
}

bool TimingSolver::getInitialValues(const ConstraintManager &constraints, const ArrayVec &objects,
                                    std::vector<std::vector<unsigned char>> &result, double &queryCost) {
    if (objects.empty())
        return true;

    bool success;

    if (EnableTimingLog) {
        success = measureTime(queryCost, [&]() -> bool {
            return solver->getInitialValues(Query(constraints, ConstantExpr::alloc(0, Expr::Bool)), objects, result);
        });
    } else {
        success = solver->getInitialValues(Query(constraints, ConstantExpr::alloc(0, Expr::Bool)), objects, result);
    }

    return success;
}

bool TimingSolver::getInitialValues(const ExecutionState &state, const ArrayVec &objects,
                                    std::vector<std::vector<unsigned char>> &result) {
    return getInitialValues(state.constraints(), objects, result, state.queryCost);
}

std::pair<ref<Expr>, ref<Expr>> TimingSolver::getRange(const ExecutionState &state, ref<Expr> expr) {
    return solver->getRange(Query(state.constraints(), expr));
}
