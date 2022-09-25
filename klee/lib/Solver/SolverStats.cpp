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

auto cexCacheTime = Statistic::create("CexCacheTime", "CCtime");
auto queries = Statistic::create("Queries", "Q");
auto queriesInvalid = Statistic::create("QueriesInvalid", "Qiv");
auto queriesValid = Statistic::create("QueriesValid", "Qv");
auto queryCacheHits = Statistic::create("QueryCacheHits", "QChits");
auto queryCacheMisses = Statistic::create("QueryCacheMisses", "QCmisses");
auto queryConstructTime = Statistic::create("QueryConstructTime", "QBtime");
auto queryConstructs = Statistic::create("QueriesConstructs", "QB");
auto queryCounterexamples = Statistic::create("QueriesCEX", "Qcex");
auto queryTime = Statistic::create("QueryTime", "Qtime");

} // namespace stats
} // namespace klee