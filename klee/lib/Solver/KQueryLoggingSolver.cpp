//===-- KQueryLoggingSolver.cpp -----------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "QueryLoggingSolver.h"

#include "klee/Expr.h"
#include "klee/Internal/Support/QueryLog.h"
#include "klee/util/ExprPPrinter.h"

using namespace klee;

///

class KQueryLoggingSolver : public QueryLoggingSolver {

private:
    ExprPPrinter *printer;

    virtual void printQuery(const Query &query, const Query *falseQuery = 0, const ArrayVec &objects = ArrayVec()) {

        std::vector<ref<Expr>> evalExprs;

        if (falseQuery) {
            evalExprs.push_back(query.expr);
        }

        const Query *q = (0 == falseQuery) ? &query : falseQuery;

        printer->printQuery(logBuffer, q->constraints, q->expr, evalExprs.begin(), evalExprs.end(), objects.begin(),
                            objects.end(), true);
    }

    KQueryLoggingSolver(SolverPtr _solver, std::string path, int queryTimeToLog)
        : QueryLoggingSolver(_solver, path, "#", queryTimeToLog), printer(ExprPPrinter::create(logBuffer)) {
    }

public:
    virtual ~KQueryLoggingSolver() {
        delete printer;
    }

    static SolverImplPtr create(SolverPtr _solver, std::string path, int queryTimeToLog) {
        return SolverImplPtr(new KQueryLoggingSolver(_solver, path, queryTimeToLog));
    }
};

///

SolverPtr klee::createKQueryLoggingSolver(SolverPtr &_solver, std::string path, int minQueryTimeToLog) {
    return Solver::create(KQueryLoggingSolver::create(_solver, path, minQueryTimeToLog));
}
