//===-- CoreStats.cpp -----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Stats/CoreStats.h"

namespace klee {
namespace stats {
auto instructions = Statistic::create("LLVMInstructions", "I");
auto forks = Statistic::create("Forks", "Forks");
auto solverTime = Statistic::create("SolverTime", "Stime");
auto completedPaths = Statistic::create("CompletedPaths", "CompletedPaths");
} // namespace stats
} // namespace klee
