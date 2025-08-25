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
StatisticPtr instructions = Statistic::create("LLVMInstructions", "I");
StatisticPtr forks = Statistic::create("Forks", "Forks");
StatisticPtr solverTime = Statistic::create("SolverTime", "Stime");
StatisticPtr completedPaths = Statistic::create("CompletedPaths", "CompletedPaths");
} // namespace stats
} // namespace klee
