/// Copyright (c) 2009 Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <memory>
#include <unordered_map>

#include <klee/Solver.h>
#include <klee/SolverFactory.h>

#ifndef KLEE_SOLVER_MANAGER_H
#define KLEE_SOLVER_MANAGER_H

namespace klee {

class ExecutionState;

class SolverManager {
private:
    SolverFactoryPtr mFactory = nullptr;
    bool mUsePerStateSolvers = false;
    SolverPtr mSolver;

    std::unordered_map<const ExecutionState *, SolverPtr> mPerStateSolvers;

    SolverManager(SolverManager &) = delete;

    SolverManager(bool usePerStateSolvers);

    SolverPtr createSolver();

    void removeStateSolvers();
    SolverPtr _solver(const ExecutionState &state) const;

public:
    static SolverManager &get();

    static SolverPtr solver(const ExecutionState &state);
    static SolverPtr solver(void) {
        return get().mSolver;
    }

    void createStateSolver(const ExecutionState &state);
    void removeState(const ExecutionState *state);

    void initialize(const SolverFactoryPtr &factory);
};
} // namespace klee

#endif
