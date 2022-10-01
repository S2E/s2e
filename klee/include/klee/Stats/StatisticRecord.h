//===-- Statistics.h --------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_STATISTIC_RECORD_H
#define KLEE_STATISTIC_RECORD_H

namespace klee {
namespace stats {

class StatisticRecord {
    friend class StatisticManager;

private:
    uint64_t *data;

public:
    StatisticRecord();
    StatisticRecord(const StatisticRecord &s);
    ~StatisticRecord() {
        delete[] data;
    }

    void zero();

    uint64_t getValue(const Statistic &s) const;
    void incrementValue(const Statistic &s, uint64_t addend) const;
    StatisticRecord &operator=(const StatisticRecord &s);
    StatisticRecord &operator+=(const StatisticRecord &sr);
};

inline void StatisticRecord::zero() {
    ::memset(data, 0, sizeof(*data) * theStatisticManager->getNumStatistics());
}

inline StatisticRecord::StatisticRecord() : data(new uint64_t[theStatisticManager->getNumStatistics()]) {
    zero();
}

inline StatisticRecord::StatisticRecord(const StatisticRecord &s)
    : data(new uint64_t[theStatisticManager->getNumStatistics()]) {
    ::memcpy(data, s.data, sizeof(*data) * theStatisticManager->getNumStatistics());
}

inline StatisticRecord &StatisticRecord::operator=(const StatisticRecord &s) {
    ::memcpy(data, s.data, sizeof(*data) * theStatisticManager->getNumStatistics());
    return *this;
}

inline void StatisticRecord::incrementValue(const Statistic &s, uint64_t addend) const {
    data[s.id] += addend;
}
inline uint64_t StatisticRecord::getValue(const Statistic &s) const {
    return data[s.id];
}

inline StatisticRecord &StatisticRecord::operator+=(const StatisticRecord &sr) {
    unsigned nStats = theStatisticManager->getNumStatistics();
    for (unsigned i = 0; i < nStats; i++)
        data[i] += sr.data[i];
    return *this;
}

} // namespace stats
} // namespace klee

#endif