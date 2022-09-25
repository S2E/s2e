//===-- SolverStats.h -------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_SOLVERSTATS_H
#define KLEE_SOLVERSTATS_H

#include "Statistic.h"

namespace klee {
namespace stats {

extern StatisticPtr cexCacheTime;
extern StatisticPtr queries;
extern StatisticPtr queriesInvalid;
extern StatisticPtr queriesValid;
extern StatisticPtr queryCacheHits;
extern StatisticPtr queryCacheMisses;
extern StatisticPtr queryConstructTime;
extern StatisticPtr queryConstructs;
extern StatisticPtr queryCounterexamples;
extern StatisticPtr queryTime;
} // namespace stats
} // namespace klee

#endif
