//===-- CoreStats.h ---------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_CORESTATS_H
#define KLEE_CORESTATS_H

#include "Statistic.h"

namespace klee {
namespace stats {

extern StatisticPtr instructions;
extern StatisticPtr forkTime;
extern StatisticPtr solverTime;

/// The number of process forks.
extern StatisticPtr forks;

extern StatisticPtr completedPaths;

} // namespace stats
} // namespace klee

#endif
