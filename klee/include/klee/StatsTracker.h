//===-- StatsTracker.h ------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_STATSTRACKER_H
#define KLEE_STATSTRACKER_H

#include <iostream>
#include <llvm/Support/raw_ostream.h>
#include <set>

namespace klee {
class ExecutionState;
class Executor;
class InstructionInfoTable;
class InterpreterHandler;
struct KInstruction;
struct StackFrame;

class StatsTracker {
protected:
    friend class WriteStatsTimer;
    friend class WriteIStatsTimer;

    Executor &executor;
    std::string objectFilename;

    llvm::raw_ostream *statsFile, *istatsFile;
    double startWallTime;

public:
    static bool useStatistics();

protected:
    void updateStateStatistics(uint64_t addend);
    virtual void writeStatsHeader();
    virtual void writeStatsLine();
    virtual void writeIStats();

public:
    StatsTracker(Executor &_executor, std::string _objectFilename);
    virtual ~StatsTracker();

    void writeHeaders();

    // called when execution is done and stats files should be flushed
    void done();

    /// Return time in seconds since execution start.
    double elapsed();
};
} // namespace klee

#endif
