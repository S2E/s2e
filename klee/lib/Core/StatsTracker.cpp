//===-- StatsTracker.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/StatsTracker.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/System/Time.h"
#include "klee/Statistics.h"

#include "klee/CoreStats.h"
#include "klee/Executor.h"
#include "klee/SolverStats.h"
#include "klee/UserSearcher.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"

#include <fstream>
#include <iostream>

using namespace klee;
using namespace llvm;

///

namespace {
cl::opt<bool> OutputStats("output-stats", cl::desc("Write running stats trace file"), cl::init(true));

cl::opt<bool> OutputIStats("output-istats", cl::desc("Write instruction level statistics (in callgrind format)"),
                           cl::init(false));

cl::opt<double> StatsWriteInterval("stats-write-interval",
                                   cl::desc("Approximate number of seconds between stats writes (default: 1.0)"),
                                   cl::init(1.));

cl::opt<double> IStatsWriteInterval("istats-write-interval",
                                    cl::desc("Approximate number of seconds between istats writes (default: 10.0)"),
                                    cl::init(10.));

// XXX I really would like to have dynamic rate control for something like this.
cl::opt<bool> UseCallPaths("use-call-paths", cl::desc("Enable calltree tracking for instruction level statistics"),
                           cl::init(true));
} // namespace

///

bool StatsTracker::useStatistics() {
    return OutputStats || OutputIStats;
}

namespace klee {
class WriteIStatsTimer : public Executor::Timer {
    StatsTracker *statsTracker;

public:
    WriteIStatsTimer(StatsTracker *_statsTracker) : statsTracker(_statsTracker) {
    }
    ~WriteIStatsTimer() {
    }

    void run() {
        statsTracker->writeIStats();
    }
};

class WriteStatsTimer : public Executor::Timer {
    StatsTracker *statsTracker;

public:
    WriteStatsTimer(StatsTracker *_statsTracker) : statsTracker(_statsTracker) {
    }
    ~WriteStatsTimer() {
    }

    void run() {
        statsTracker->writeStatsLine();
    }
};
} // namespace klee

StatsTracker::StatsTracker(Executor &_executor, std::string _objectFilename)
    : executor(_executor), objectFilename(_objectFilename), statsFile(0), istatsFile(0),
      startWallTime(util::getWallTime()) {
}

void StatsTracker::writeHeaders() {
    if (OutputStats) {
        if (statsFile) {
            delete statsFile;
        }

        statsFile = executor.interpreterHandler->openOutputFile("run.stats");
        assert(statsFile && "unable to open statistics trace file");
        writeStatsHeader();
        writeStatsLine();

        executor.addTimer(new WriteStatsTimer(this), StatsWriteInterval);
    }

    if (OutputIStats) {
        if (istatsFile) {
            delete istatsFile;
        }

        istatsFile = executor.interpreterHandler->openOutputFile("run.istats");
        assert(istatsFile && "unable to open istats file");

        executor.addTimer(new WriteIStatsTimer(this), IStatsWriteInterval);
    }
}

StatsTracker::~StatsTracker() {
    if (statsFile)
        delete statsFile;
    if (istatsFile)
        delete istatsFile;
}

void StatsTracker::done() {
    if (statsFile)
        writeStatsLine();
    if (OutputIStats)
        writeIStats();
}

///

void StatsTracker::writeStatsHeader() {
    *statsFile << "('Instructions',"
               << "'UserTime',"
               << "'NumStates',"
               << "'NumQueries',"
               << "'NumQueryConstructs',"
               << "'NumObjects',"
               << "'WallTime',"
               << "'CoveredInstructions',"
               << "'UncoveredInstructions',"
               << "'QueryTime',"
               << "'SolverTime',"
               << "'CexCacheTime',"
               << "'ForkTime',"
               << "'ResolveTime',"
               << ")\n";
    statsFile->flush();
}

double StatsTracker::elapsed() {
    return util::getWallTime() - startWallTime;
}

void StatsTracker::writeStatsLine() {
    *statsFile << "(" << stats::instructions << "," << util::getUserTime() << "," << executor.states.size() << ","
               << "," << stats::queries << "," << stats::queryConstructs << "," << 0 // was numObjects
               << "," << elapsed() << "," << stats::coveredInstructions << "," << stats::uncoveredInstructions << ","
               << stats::queryTime / 1000000. << "," << stats::solverTime / 1000000. << ","
               << stats::cexCacheTime / 1000000. << "," << stats::forkTime / 1000000. << ","
               << stats::resolveTime / 1000000. << ")\n";
    statsFile->flush();
}

void StatsTracker::updateStateStatistics(uint64_t addend) {
}

void StatsTracker::writeIStats() {
}
