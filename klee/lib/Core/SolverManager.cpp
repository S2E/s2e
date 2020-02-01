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

#include <llvm/Support/CommandLine.h>

#include <klee/SolverManager.h>

namespace {
using namespace llvm;
cl::opt<bool> PerStateSolver("per-state-solver", cl::desc("Create solver instance for each state"), cl::init(false));
} // namespace

namespace klee {

SolverManager::SolverManager(bool usePerStateSolvers) {
    mUsePerStateSolvers = usePerStateSolvers;
}

SolverManager &SolverManager::get() {
    static SolverManager mgr(PerStateSolver);
    return mgr;
}

void SolverManager::initialize(const std::shared_ptr<SolverFactory> &factory) {
    removeStateSolvers();
    mFactory = factory;
    mSolver = createTimingSolver();
}

std::shared_ptr<TimingSolver> SolverManager::createTimingSolver() {
    assert(mFactory);
    Solver *endSolver = mFactory->createEndSolver();
    Solver *solver = mFactory->decorateSolver(endSolver);
    return std::shared_ptr<TimingSolver>(new TimingSolver(solver));
}

void SolverManager::createStateSolver(const ExecutionState &state) {
    if (!mUsePerStateSolvers) {
        return;
    }

    if (mPerStateSolvers.find(&state) == mPerStateSolvers.end()) {
        mPerStateSolvers[&state] = createTimingSolver();
    }
}

void SolverManager::removeStateSolvers() {
    mPerStateSolvers.clear();
}

std::shared_ptr<TimingSolver> SolverManager::_solver(const ExecutionState &state) const {
    if (!mUsePerStateSolvers) {
        return mSolver;
    } else {
        auto it = mPerStateSolvers.find(&state);
        assert(it != mPerStateSolvers.end() && "Can't find solver for given state");
        return it->second;
    }
}

void SolverManager::removeState(const ExecutionState *state) {
    if (mUsePerStateSolvers) {
        mPerStateSolvers.erase(state);
    }
}

std::shared_ptr<TimingSolver> SolverManager::solver(const ExecutionState &state) {
    return get()._solver(state);
}
} // namespace klee
