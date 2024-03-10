//===-- Statistics.cpp ----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <mutex>
#include <sstream>

#include "klee/Stats/Statistic.h"
#include "klee/Stats/StatisticManager.h"

namespace klee {
namespace stats {

static StatisticManagerPtr s_statsManager = nullptr;
static std::mutex s_mutex;

StatisticManager::StatisticManager() {
}
StatisticManager::~StatisticManager() {
}

StatisticManagerPtr getStatisticManager() {
    assert(s_statsManager);
    return s_statsManager;
}

static StatisticManagerPtr getOrCreateStatisticManager() {
    std::unique_lock lock(s_mutex);

    if (s_statsManager == nullptr) {
        s_statsManager = StatisticManager::create();
    }
    return s_statsManager;
}

std::string StatisticManager::getCSVHeader() const {
    std::stringstream ss;
    for (size_t i = 0; i < stats.size(); ++i) {
        ss << stats[i]->getName();
        if (i < stats.size() - 1) {
            ss << ",";
        }
    }
    ss << "\n";
    return ss.str();
}

std::string StatisticManager::getCSVLine() const {
    std::stringstream ss;
    for (size_t i = 0; i < globalStats.size(); ++i) {
        ss << globalStats[i];
        if (i < globalStats.size() - 1) {
            ss << ",";
        }
    }
    ss << "\n";
    return ss.str();
}

/* *** */

std::atomic<unsigned> Statistic::s_id(0);

Statistic::Statistic(const std::string &_name, const std::string &_shortName)
    : mId(s_id.fetch_add(1, std::memory_order_seq_cst)), mName(_name), mShortName(_shortName) {
}

Statistic::~Statistic() {
}

StatisticPtr Statistic::create(const std::string &_name, const std::string &_shortName) {
    auto ret = StatisticPtr(new Statistic(_name, _shortName));
    if (ret != nullptr) {
        getOrCreateStatisticManager()->registerStatistic(ret);
    }

    return ret;
}

Statistic &Statistic::operator+=(const uint64_t addend) {
    getStatisticManager()->incrementStatistic(*this, addend);
    return *this;
}

uint64_t Statistic::getValue() const {
    return getStatisticManager()->getValue(*this);
}

void Statistic::setValue(uint64_t value) {
    return getStatisticManager()->setValue(*this, value);
}

} // namespace stats
} // namespace klee
