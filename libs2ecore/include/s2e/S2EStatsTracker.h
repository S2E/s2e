///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_STATSTRACKER_H
#define S2E_STATSTRACKER_H

#include <klee/Statistic.h>
#include <klee/StatsTracker.h>

namespace klee {
namespace stats {
extern klee::Statistic translationBlocks;
extern klee::Statistic translationBlocksConcrete;
extern klee::Statistic translationBlocksKlee;

extern klee::Statistic availableTranslationBlocks;
extern klee::Statistic availableTranslationBlocksInstrumented;

extern klee::Statistic cpuInstructions;
extern klee::Statistic cpuInstructionsConcrete;
extern klee::Statistic cpuInstructionsKlee;

extern klee::Statistic concreteModeTime;
extern klee::Statistic symbolicModeTime;

extern klee::Statistic completedPaths;
extern klee::Statistic completedSpeculativePaths;

extern klee::Statistic totalBasicBlocks;
extern klee::Statistic coveredBasicBlocks;

extern klee::Statistic bugs;
} // namespace stats
} // namespace klee

namespace s2e {

class S2EStatsTracker : public klee::StatsTracker {
public:
    S2EStatsTracker(klee::Executor &_executor, std::string _objectFilename) : StatsTracker(_executor, _objectFilename) {
    }

    static uint64_t getProcessMemoryUsage();

protected:
    void writeStatsHeader();
    void writeStatsLine();
};

class S2EExecutionState;

class S2EStateStats {
public:
    // Statistics counters
    uint64_t m_statTranslationBlockConcrete;
    uint64_t m_statTranslationBlockSymbolic;
    uint64_t m_statInstructionCountSymbolic;

    // Counter values at the last check
    uint64_t m_laststatTranslationBlockConcrete;
    uint64_t m_laststatTranslationBlockSymbolic;
    uint64_t m_laststatInstructionCount;
    uint64_t m_laststatInstructionCountConcrete;
    uint64_t m_laststatInstructionCountSymbolic;

public:
    S2EStateStats();
    void updateStats(S2EExecutionState *state);
};

} // namespace s2e

#endif // S2ESTATSTRACKER_H
