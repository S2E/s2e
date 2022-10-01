//===-- TimerStatIncrementer.h ----------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_TIMERSTATINCREMENTER_H
#define KLEE_TIMERSTATINCREMENTER_H

#include "klee/Internal/Support/Timer.h"
#include "Statistic.h"

namespace klee {
namespace stats {
class TimerStatIncrementer {
private:
    WallTimer timer;
    StatisticPtr statistic;

public:
    TimerStatIncrementer(StatisticPtr &_statistic) : statistic(_statistic) {
    }

    ~TimerStatIncrementer() {
        *statistic += timer.check();
    };

    uint64_t check() {
        return timer.check();
    }
};
} // namespace stats
} // namespace klee

#endif
