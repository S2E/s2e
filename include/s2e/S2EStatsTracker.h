///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    static void writeCacheStats(llvm::raw_ostream &os);

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
