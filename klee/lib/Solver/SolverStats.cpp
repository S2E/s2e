//===-- SolverStats.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Stats/SolverStats.h"

namespace klee {
namespace stats {

StatisticPtr cexCacheTime = Statistic::create("CexCacheTime", "CCtime");
StatisticPtr queries = Statistic::create("Queries", "Q");
StatisticPtr queriesInvalid = Statistic::create("QueriesInvalid", "Qiv");
StatisticPtr queriesValid = Statistic::create("QueriesValid", "Qv");
StatisticPtr queryCacheHits = Statistic::create("QueryCacheHits", "QChits");
StatisticPtr queryCacheMisses = Statistic::create("QueryCacheMisses", "QCmisses");
StatisticPtr queryConstructTime = Statistic::create("QueryConstructTime", "QBtime");
StatisticPtr queryConstructs = Statistic::create("QueriesConstructs", "QB");
StatisticPtr queryCounterexamples = Statistic::create("QueriesCEX", "Qcex");
StatisticPtr queryTime = Statistic::create("QueryTime", "Qtime");

} // namespace stats
} // namespace klee