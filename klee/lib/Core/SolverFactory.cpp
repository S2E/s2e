/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "klee/SolverFactory.h"
#include "klee/Common.h"
#include "klee/Config/config.h"
#include "klee/Interpreter.h"
#include "klee/Solver.h"

#include <llvm/Support/CommandLine.h>

using namespace llvm;

namespace {

enum EndSolverType { SOLVER_Z3 };

cl::opt<EndSolverType> EndSolver("end-solver", cl::desc("End solver to use"),
                                 cl::values(clEnumValN(SOLVER_Z3, "z3", "The Z3 solver")), cl::init(SOLVER_Z3));

enum SolverIncrementalityType { INCREMENTAL_NONE, INCREMENTAL_STACK, INCREMENTAL_ASSUMPTIONS };

cl::opt<SolverIncrementalityType> SolverIncrementality(
    "end-solver-increm", cl::desc("Solver incrementality type (when available)"),
    cl::values(clEnumValN(INCREMENTAL_NONE, "none", "No incrementality"),
               clEnumValN(INCREMENTAL_STACK, "stack", "Context stack incrementality"),
               clEnumValN(INCREMENTAL_ASSUMPTIONS, "assumptions", "Assumption-based incrementality")),
    cl::init(INCREMENTAL_NONE));

// The counter example cache may have bad interactions with
// concolic mode. Disabled by default.
cl::opt<bool> UseCexCache("use-cex-cache", cl::init(false), cl::desc("Use counterexample caching"));

cl::opt<int> MinQueryTimeToLog("min-query-time-to-log", cl::init(0), cl::value_desc("milliseconds"),
                               cl::desc("Set time threshold (in ms) for queries logged in files. Only queries longer "
                                        "than threshold will be logged. default=0). Set this param to a negative "
                                        "value to log timeouts only."));

/// The different query logging solver that can be switched on/off
enum QueryLoggingSolverType {
    ALL_KQUERY,    ///< Log all queries (un-optimised) in .kquery (KQuery) format
    ALL_SMTLIB,    ///< Log all queries (un-optimised) in .smt2 (SMT-LIBv2) format
    SOLVER_KQUERY, ///< Log all queries passed to solver (optimised) in .kquery (KQuery) format
    SOLVER_SMTLIB, ///< Log queries passed to solver (optimised) in .smt2 (SMT-LIBv2) format
};

cl::bits<QueryLoggingSolverType>
    queryLoggingOptions("use-query-log",
                        cl::desc("Log queries to a file. Multiple options can be "
                                 "separated by a comma. By default nothing is logged."),
                        cl::values(clEnumValN(ALL_KQUERY, "all:kquery", "All queries in .kquery (KQuery) format"),
                                   clEnumValN(ALL_SMTLIB, "all:smt2", "All queries in .smt2 (SMT-LIBv2) format"),
                                   clEnumValN(SOLVER_KQUERY, "solver:kquery",
                                              "All queries reaching the solver in .kqery "
                                              "(KQuery) format"),
                                   clEnumValN(SOLVER_SMTLIB, "solver:smt2",
                                              "All queries reaching the solver in .smt2 "
                                              "(SMT-LIBv2) format")),
                        cl::CommaSeparated);

cl::opt<bool> UseEndQueryPCLog("use-end-query-pc-log", cl::init(false));

cl::opt<bool> UseFastCexSolver("use-fast-cex-solver", cl::init(false));

cl::opt<bool> UseCache("use-cache", cl::init(true), cl::desc("Use validity caching"));

cl::opt<bool> UseIndependentSolver("use-independent-solver", cl::init(true), cl::desc("Use constraint independence"));

cl::opt<bool> DebugValidateSolver("debug-validate-solver", cl::init(false));
} // namespace

namespace klee {

DefaultSolverFactory::DefaultSolverFactory(InterpreterHandler *ih) : ih_(ih) {
}

Solver *DefaultSolverFactory::createEndSolver() {
    if (EndSolver == SOLVER_Z3) {
#ifdef ENABLE_Z3
        switch (SolverIncrementality) {
            case INCREMENTAL_NONE:
                return Z3Solver::createResetSolver();
            case INCREMENTAL_STACK:
                return Z3Solver::createStackSolver();
            case INCREMENTAL_ASSUMPTIONS:
                return Z3Solver::createAssumptionSolver();
        }
#else
        pabort("Z3 support not compiled");
#endif
    }
    return NULL;
}

Solver *DefaultSolverFactory::decorateSolver(Solver *end_solver) {
    Solver *solver = end_solver;

    if (queryLoggingOptions.isSet(SOLVER_KQUERY)) {
        solver = createKQueryLoggingSolver(solver, ih_->getOutputFilename(SOLVER_QUERIES_KQUERY_FILE_NAME),
                                           MinQueryTimeToLog);
    }

    if (queryLoggingOptions.isSet(SOLVER_SMTLIB)) {
        solver =
            createSMTLIBLoggingSolver(solver, ih_->getOutputFilename(SOLVER_QUERIES_SMT2_FILE_NAME), MinQueryTimeToLog);
    }

    if (UseFastCexSolver) {
        solver = createFastCexSolver(solver);
    }

    if (UseCexCache) {
        solver = createCexCachingSolver(solver);
    }

    if (UseCache) {
        solver = createCachingSolver(solver);
    }

    // FIXME: The check should be more generic (e.g., enable only for
    // non-incremental solvers)
    if (UseIndependentSolver && (EndSolver != SOLVER_Z3)) {
        solver = createIndependentSolver(solver);
    }

    if (DebugValidateSolver) {
        solver = createValidatingSolver(solver, end_solver);
    }

    if (queryLoggingOptions.isSet(ALL_KQUERY)) {
        solver =
            createKQueryLoggingSolver(solver, ih_->getOutputFilename(ALL_QUERIES_KQUERY_FILE_NAME), MinQueryTimeToLog);
    }

    if (queryLoggingOptions.isSet(ALL_SMTLIB)) {
        solver =
            createSMTLIBLoggingSolver(solver, ih_->getOutputFilename(ALL_QUERIES_SMT2_FILE_NAME), MinQueryTimeToLog);
    }

    return solver;
}
} // namespace klee
