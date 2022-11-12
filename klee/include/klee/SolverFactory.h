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

#ifndef SOLVERFACTORY_H_
#define SOLVERFACTORY_H_

#include <filesystem>
#include <string>
#include "Solver.h"

namespace klee {

class Solver;

class SolverFactory {
protected:
    SolverFactory() {
    }

public:
    virtual ~SolverFactory() {
    }
    virtual SolverPtr createEndSolver() = 0;
    virtual SolverPtr decorateSolver(SolverPtr &end_solver) = 0;
};

using SolverFactoryPtr = std::shared_ptr<SolverFactory>;

class DefaultSolverFactory : public SolverFactory {
private:
    std::filesystem::path m_outputDir;
    DefaultSolverFactory(const std::filesystem::path &outputDir);

    std::filesystem::path getOutputFileName(const std::string &fileName) const;

public:
    virtual SolverPtr createEndSolver();
    virtual SolverPtr decorateSolver(SolverPtr &end_solver);

    static SolverFactoryPtr create(const std::filesystem::path &outputDir) {
        return SolverFactoryPtr(new DefaultSolverFactory(outputDir));
    }
};
} // namespace klee

#endif /* SOLVERFACTORY_H_ */
