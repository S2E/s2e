//===-- Timer.cpp ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/Support/Timer.h"

#include "klee/Config/config.h"
#if (LLVM_VERSION_MAJOR == 2 && LLVM_VERSION_MINOR < 7)
#include "llvm/System/Process.h"
#else
#include "llvm/Support/Process.h"
#endif

using namespace klee;
using namespace llvm;

WallTimer::WallTimer() {
    m_start = std::chrono::steady_clock::now();
}

uint64_t WallTimer::check() {
    auto now = std::chrono::steady_clock::now();
    auto diff = now - m_start;
    return std::chrono::duration_cast<std::chrono::microseconds>(diff).count();
}
