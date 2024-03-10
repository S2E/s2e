//===-- Statistics.h --------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_STATISTIC_MANAGER_H
#define KLEE_STATISTIC_MANAGER_H

#include <cassert>
#include <memory>
#include <unordered_map>
#include <vector>

#include "Statistic.h"

namespace klee {
namespace stats {

class StatisticManager;
using StatisticManagerPtr = std::shared_ptr<StatisticManager>;

class StatisticManager {
private:
    std::vector<StatisticPtr> stats;
    std::vector<uint64_t> globalStats;
    std::unordered_map<std::string /* name */, StatisticPtr> mStats;

    StatisticManager();

public:
    ~StatisticManager();

    static StatisticManagerPtr create() {
        return StatisticManagerPtr(new StatisticManager());
    }

    unsigned getNumStatistics() {
        return stats.size();
    }

    StatisticPtr &getStatistic(unsigned i) {
        return stats[i];
    }

    void registerStatistic(StatisticPtr &s) {
        assert(globalStats.size() == stats.size());
        assert(s->getID() == stats.size());
        stats.push_back(s);
        globalStats.push_back(0);
        mStats[s->getName()] = s;
    }

    void incrementStatistic(const Statistic &s, uint64_t addend) {
        globalStats[s.getID()] += addend;
    }

    uint64_t getValue(const Statistic &s) const {
        return globalStats[s.getID()];
    }

    void setValue(const Statistic &s, uint64_t value) {
        globalStats[s.getID()] = value;
    }

    int getStatisticID(const std::string &name) const {
        auto stat = getStatisticByName(name);
        if (stat == nullptr) {
            return -1;
        }

        return stat->getID();
    }

    StatisticPtr getStatisticByName(const std::string &name) const {
        auto it = mStats.find(name);
        if (it == mStats.end()) {
            return nullptr;
        }

        return (*it).second;
    }

    std::string getCSVHeader() const;
    std::string getCSVLine() const;
};

StatisticManagerPtr getStatisticManager();

} // namespace stats
} // namespace klee

#endif