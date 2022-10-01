//===-- Statistic.h ---------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_STATISTIC_H
#define KLEE_STATISTIC_H

#include <atomic>
#include <memory>
#include <string>
#include "llvm/Support/DataTypes.h"

namespace klee {
namespace stats {

class Statistic;

using StatisticPtr = std::shared_ptr<Statistic>;

/// Statistic - A named statistic instance.
///
/// The Statistic class holds information about the statistic, but
/// not the actual values. Values are managed by the global
/// StatisticManager to enable transparent support for instruction
/// level and call path level statistics.
class Statistic {
private:
    static std::atomic<unsigned> s_id;
    const unsigned mId;
    const std::string mName;
    const std::string mShortName;

    Statistic(const std::string &_name, const std::string &_shortName);

public:
    ~Statistic();

    static StatisticPtr create(const std::string &_name, const std::string &_shortName);

    /// getID - Get the unique statistic ID.
    unsigned getID() const {
        return mId;
    }

    /// getName - Get the statistic name.
    const std::string &getName() const {
        return mName;
    }

    /// getShortName - Get the "short" statistic name, used in
    /// callgrind output for example.
    const std::string &getShortName() const {
        return mShortName;
    }

    /// getValue - Get the current primary statistic value.
    uint64_t getValue() const;

    void setValue(uint64_t value);

    /// operator uint64_t - Get the current primary statistic value.
    operator uint64_t() const {
        return getValue();
    }

    /// operator++ - Increment the statistic by 1.
    Statistic &operator++() {
        return (*this += 1);
    }

    /// operator+= - Increment the statistic by \arg addend.
    Statistic &operator+=(const uint64_t addend);
};
} // namespace stats
} // namespace klee

#endif
