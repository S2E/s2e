///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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
///

#ifndef KLEE_IEXECUTIONSTATE_H
#define KLEE_IEXECUTIONSTATE_H

#include <vector>

#include "klee/AddressSpace.h"
#include "klee/Solver.h"
#include "klee/util/Assignment.h"

namespace klee {

class IExecutionState {
public:
    virtual SolverPtr solver() = 0;
    virtual AddressSpace &addressSpace() = 0;
    virtual const AddressSpace &addressSpace() const = 0;
    virtual const std::vector<ArrayPtr> &symbolics() const = 0;
    virtual const AssignmentPtr concolics() const = 0;
    virtual void setConcolics(AssignmentPtr concolics) = 0;
};

} // namespace klee

#endif
