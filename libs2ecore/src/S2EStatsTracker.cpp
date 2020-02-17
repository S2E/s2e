///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#include <s2e/S2EStatsTracker.h>

#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <klee/CoreStats.h>
#include <klee/Internal/System/Time.h>
#include <klee/SolverStats.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Process.h>

#include <sstream>

#include <inttypes.h>
#include <stdio.h>

#include <s2e/cpu.h>

#ifdef CONFIG_DARWIN
#include <mach/mach.h>
#include <mach/mach_traps.h>
#endif

#ifdef CONFIG_WIN32
#include <psapi.h>
#include <windows.h>
#endif

namespace klee {
namespace stats {
Statistic translationBlocks("TranslationBlocks", "TBs");
Statistic translationBlocksConcrete("TranslationBlocksConcrete", "TBsConcrete");
Statistic translationBlocksKlee("TranslationBlocksKlee", "TBsKlee");

Statistic availableTranslationBlocks("AvailableTranslationBlocks", "AvlTBs");
Statistic availableTranslationBlocksInstrumented("AvailableTranslationBlocksInstrumented", "AvlTBsinst");

Statistic cpuInstructions("CpuInstructions", "CpuI");
Statistic cpuInstructionsConcrete("CpuInstructionsConcrete", "CpuIConcrete");
Statistic cpuInstructionsKlee("CpuInstructionsKlee", "CpuIKlee");

Statistic concreteModeTime("ConcreteModeTime", "ConcModeTime");
Statistic symbolicModeTime("SymbolicModeTime", "SymbModeTime");

Statistic completedPaths("CompletedPaths", "CompletedPaths");

Statistic totalBasicBlocks("TotalBasicBlocks", "TotalBasicBlocks");
Statistic coveredBasicBlocks("CoveredBasicBlocks", "CoveredBasicBlocks");

Statistic bugs("Bugs", "Bugs");
} // namespace stats
} // namespace klee

using namespace klee;
using namespace llvm;

namespace {
cl::opt<bool> CsvOutput("output-csv-stats", cl::desc("Output run.stats in CSV format"), cl::init(true));
}

namespace s2e {

/**
 *  Replaces the broken LLVM functions
 */
uint64_t S2EStatsTracker::getProcessMemoryUsage() {
#if defined(CONFIG_WIN32)

    PROCESS_MEMORY_COUNTERS Memory;
    HANDLE CurrentProcess = GetCurrentProcess();

    if (!GetProcessMemoryInfo(CurrentProcess, &Memory, sizeof(Memory))) {
        return 0;
    }

    return Memory.PagefileUsage;

#elif defined(CONFIG_DARWIN)
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (KERN_SUCCESS != task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t) &t_info, &t_info_count)) {
        return -1;
    }
    // resident size is in t_info.resident_size;
    // return t_info.virtual_size;
    return t_info.resident_size;

#else
    pid_t myPid = getpid();
    std::stringstream ss;
    ss << "/proc/" << myPid << "/status";

    FILE *fp = fopen(ss.str().c_str(), "r");
    if (!fp) {
        return 0;
    }

    uint64_t peakMem = 0;

    char buffer[512];
    while (!peakMem && fgets(buffer, sizeof(buffer), fp)) {
        if (sscanf(buffer, "VmSize: %" PRIu64, &peakMem)) {
            break;
        }
    }

    fclose(fp);

    return peakMem * 1024;
#endif
}

void S2EStatsTracker::writeStatsHeader() {
    // clang-format off
    const char *columns[]= {
        "NumStates",
        "CompletedPaths",
        "CoveredBasicBlocks",
        "TotalBasicBlocks",
        "Bugs",
        "NumQueries",
        "NumQueryConstructs",
        "TranslationBlocks",
        "TranslationBlocksConcrete",
        "TranslationBlocksKlee",

        "AvailableTranslationBlocks",
        "AvailableTranslationBlocksInstrumented",

        "CpuInstructions",
        "CpuInstructionsConcrete",
        "CpuInstructionsKlee",
        "ConcreteModeTime",
        "SymbolicModeTime",
        "UserTime",
        "WallTime",
        "QueryTime",
        "SolverTime",
        "CexCacheTime",
        "ForkTime",
        "ResolveTime",
        "MemoryUsage"
    };
    // clang-format on

    if (!CsvOutput) {
        *statsFile << "(";
    }

    unsigned count = sizeof(columns) / sizeof(columns[0]);
    for (unsigned i = 0; i < count; ++i) {
        *statsFile << columns[i];
        if (i < count - 1) {
            *statsFile << ",";
        }
    }

    if (!CsvOutput) {
        *statsFile << ")";
    }

    *statsFile << "\n";

    statsFile->flush();
}

void S2EStatsTracker::writeStatsLine() {
    if (!CsvOutput) {
        *statsFile << "(";
    }

    // clang-format off
    *statsFile
             << executor.getStatesCount()
             << "," << stats::completedPaths
             << "," << stats::coveredBasicBlocks
             << "," << stats::totalBasicBlocks
             << "," << stats::bugs
             << "," << stats::queries
             << "," << stats::queryConstructs
             << "," << stats::translationBlocks
             << "," << stats::translationBlocksConcrete
             << "," << stats::translationBlocksKlee

             << "," << stats::availableTranslationBlocks
             << "," << stats::availableTranslationBlocksInstrumented

             << "," << stats::cpuInstructions
             << "," << stats::cpuInstructionsConcrete
             << "," << stats::cpuInstructionsKlee
             << "," << stats::concreteModeTime / 1000000.
             << "," << stats::symbolicModeTime / 1000000.
             << "," << util::getUserTime()
             << "," << elapsed()
             << "," << stats::queryTime / 1000000.
             << "," << stats::solverTime / 1000000.
             << "," << stats::cexCacheTime / 1000000.
             << "," << stats::forkTime / 1000000.
             << "," << stats::resolveTime / 1000000.
             << "," << getProcessMemoryUsage();
    // clang-format on
    if (!CsvOutput) {
        *statsFile << ")";
    }

    *statsFile << "\n";

    statsFile->flush();
}

S2EStateStats::S2EStateStats()
    : m_statTranslationBlockConcrete(0), m_statTranslationBlockSymbolic(0), m_statInstructionCountSymbolic(0),
      m_laststatTranslationBlockConcrete(0), m_laststatTranslationBlockSymbolic(0), m_laststatInstructionCount(0),
      m_laststatInstructionCountConcrete(0), m_laststatInstructionCountSymbolic(0) {
}

void S2EStateStats::updateStats(S2EExecutionState *state) {
    // Updating translation block counts
    uint64_t tbcdiff = m_statTranslationBlockConcrete - m_laststatTranslationBlockConcrete;
    stats::translationBlocksConcrete += tbcdiff;
    m_laststatTranslationBlockConcrete = m_statTranslationBlockConcrete;

    uint64_t sbcdiff = m_statTranslationBlockSymbolic - m_laststatTranslationBlockSymbolic;
    stats::translationBlocksKlee += sbcdiff;
    m_laststatTranslationBlockSymbolic = m_statTranslationBlockSymbolic;

    stats::translationBlocks += tbcdiff + sbcdiff;

    // Updating instruction counts

    // KLEE icount
    uint64_t sidiff = m_statInstructionCountSymbolic - m_laststatInstructionCountSymbolic;
    stats::cpuInstructionsKlee += sidiff;
    m_laststatInstructionCountSymbolic = m_statInstructionCountSymbolic;

    // Total icount
    // TODO: need lightweight method to compute that
    uint64_t totalICount = 0;
    uint64_t tidiff = totalICount - m_laststatInstructionCount;
    stats::cpuInstructions += tidiff;
    m_laststatInstructionCount = totalICount;

    // Concrete icount
    uint64_t ccount = totalICount - m_statInstructionCountSymbolic;
    uint64_t cidiff = ccount - m_laststatInstructionCountConcrete;
    stats::cpuInstructionsConcrete += cidiff;
    m_laststatInstructionCountConcrete = ccount;
}

} // namespace s2e
