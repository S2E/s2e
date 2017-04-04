///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#define __STDC_FORMAT_MACROS 1

#include "llvm/Support/CommandLine.h"

#include "lib/BinaryReaders/Library.h"
#include "lib/ExecutionTracer/InstructionCounter.h"
#include "lib/ExecutionTracer/ModuleParser.h"
#include "lib/ExecutionTracer/Path.h"
#include "lib/ExecutionTracer/TestCase.h"

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>

#include <fstream>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdio.h>
//#include "icounter.h"

using namespace llvm;
using namespace s2etools;

namespace {

cl::list<std::string> TraceFiles(
    "trace", llvm::cl::value_desc("Input trace"), llvm::cl::Prefix,
    llvm::cl::desc(
        "Specify an execution trace file. The trace must be generated with InstructionCounter plugin enabled."));

cl::opt<std::string> LogDir("outputdir", cl::desc("Store the results into the given folder"), cl::init("."));

cl::list<std::string> ModPath("modpath", cl::desc("Path to modules"));
}

namespace s2etools {

#if 0
InstructionCounterTool::InstructionCounterTool(Library *lib, ModuleCache *cache, LogEvents *events)
{
    m_events = events;
    m_connection = events->onEachItem.connect(
            sigc::mem_fun(*this, &ForkProfiler::onItem)
            );
    m_cache = cache;
    m_library = lib;
}

InstructionCounterTool::~InstructionCounterTool()
{
    m_connection.disconnect();
}

void InstructionCounterTool::onItem(unsigned traceIndex,
            const s2e::plugins::ExecutionTraceItemHeader &hdr,
            void *item)
{
    if (hdr.type != s2e::plugins::TRACE_ICOUNT) {
        return;
    }

    const s2e::plugins::ExecutionTraceICount *te =
            (const s2e::plugins::ExecutionTraceICount*) item;



}
#endif
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " debugger");

    Library library;
    library.setPaths(ModPath);

    LogParser parser;
    PathBuilder pb(&parser);
    parser.parse(TraceFiles);

    ModuleCache mc(&pb);

    InstructionCounter icounter(&pb);
    TestCase testCase(&pb);

    pb.processTree();

    PathSet paths;
    PathSet::const_iterator pit;

    pb.getPaths(paths);

    std::string outFileStr = LogDir + "/icount.log";
    std::ofstream outFile(outFileStr.c_str());

    outFile << "#Path ICount TestCase" << std::endl;

    for (pit = paths.begin(); pit != paths.end(); ++pit) {
        outFile << std::dec << *pit << ": ";

        ItemProcessorState *state = pb.getState(&icounter, *pit);
        InstructionCounterState *ics = static_cast<InstructionCounterState *>(state);

        if (ics) {
            uint64_t icount = ics->getCount();
            outFile << std::dec << icount << " ";
        } else {
            outFile << "No instruction count ";
        }

        state = pb.getState(&testCase, *pit);
        TestCaseState *testCaseState = static_cast<TestCaseState *>(state);
        if (testCaseState) {
            testCaseState->printInputsLine(outFile);
        } else {
            outFile << "No test cases in the trace";
        }

        outFile << std::endl;
    }

    return 0;
}
