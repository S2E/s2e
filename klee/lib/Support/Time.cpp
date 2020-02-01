//===-- Time.cpp ----------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/System/Time.h"
#include <chrono>
#include <sys/resource.h>

namespace klee {

double util::getUserTime() {
    rusage usage{};
    auto ret = ::getrusage(RUSAGE_SELF, &usage);

    if (ret) {
        return 0.0;
    } else {
        return (double) usage.ru_utime.tv_sec + usage.ru_utime.tv_usec * 1e-6;
    }
}

double util::getWallTime() {
    auto tp = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::duration<double>>(tp.time_since_epoch()).count();
}
} // namespace klee
