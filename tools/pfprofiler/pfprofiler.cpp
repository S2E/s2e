///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/*#define __STDC_CONSTANT_MACROS 1
#define __STDC_LIMIT_MACROS 1
#define __STDC_FORMAT_MACROS 1
*/

#include <llvm/Support/CommandLine.h>

#include <fstream>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <stdio.h>

#include "lib/ExecutionTracer/InstructionCounter.h"
#include "lib/ExecutionTracer/ModuleParser.h"
#include "lib/ExecutionTracer/PageFault.h"
#include "lib/ExecutionTracer/Path.h"
#include "lib/ExecutionTracer/TestCase.h"

#include "CacheProfiler.h"
#include "pfprofiler.h"

#include <malloc.h>

using namespace llvm;
using namespace s2etools;
using namespace s2e::plugins;

namespace {

cl::opt<std::string> TraceFile("trace", cl::desc("<input trace>"), cl::init("ExecutionTracer.dat"));

cl::list<std::string> ModDir("moddir", cl::desc("Directory containing the binary modules"));

cl::opt<std::string> ModListRaw("modlist", cl::desc("Display debug info for the specified modules (all when empty)"),
                                cl::init(""));
std::vector<std::string> ModList;

cl::opt<std::string> AnaType("type", cl::desc("Type of analysis (cache/aggregated)"), cl::init("cache"));

cl::opt<bool> TerminatedPaths("termpath", cl::desc("Show paths that have a test case"), cl::init(true));

cl::opt<std::string> OutFile("outfile", cl::desc("Output file"), cl::init("stats.dat"));

cl::opt<std::string> OutDir("outdir", cl::desc("Output directory"), cl::init("."));

cl::opt<unsigned> CPMinMissCountFilter("cpminmisscount", cl::desc("CacheProfiler: minimum miss count to report"),
                                       cl::init(0));

cl::opt<std::string> CPFilterProcess("cpfilterprocess",
                                     cl::desc("CacheProfiler: Report modules from this address space"), cl::init(""));

cl::opt<std::string>
    FilterModule("filtermodule",
                 cl::desc("Report data for the specified modules (for tracers that collect system-wide data)"),
                 cl::init(""));

cl::opt<std::string> CpOutFile("cpoutfile", cl::desc("CacheProfiler: output file"), cl::init("stats.dat"));
}

namespace s2etools {

PfProfiler::PfProfiler(const std::string &file) {
    m_FileName = file;
    m_ModuleCache = NULL;
    m_binaries.setPaths(ModDir);
}

PfProfiler::~PfProfiler() {
}

void PfProfiler::extractAggregatedData() {
    std::ofstream statsFile;
    std::string sFile = OutDir + "/pf.stats";
    statsFile.open(sFile.c_str());

    if (TerminatedPaths) {
        statsFile << "#This report shows data for only those paths that generated a test case" << std::endl;
    }

    if (FilterModule.size() > 0) {
        statsFile << "#PageFaults and TlbMisses for module " << FilterModule << std::endl;
    }

    statsFile << "#Path TestCase PageFaults TlbMisses ICount" << std::endl;

    PathBuilder pb(&m_Parser);
    m_Parser.parse(m_FileName);

    TestCase tc(&pb);
    ModuleCache mc(&pb);
    InstructionCounter ic(&pb);
    PageFault pf(&pb, &mc);

    if (FilterModule.size() > 0) {
        pf.setModule(FilterModule);
    }

    pb.processTree();

    PathSet paths;
    pb.getPaths(paths);

    PathSet::iterator pit;

    for (pit = paths.begin(); pit != paths.end(); ++pit) {

        PageFaultState *pfs = static_cast<PageFaultState *>(pb.getState(&pf, *pit));
        TestCaseState *tcs = static_cast<TestCaseState *>(pb.getState(&tc, *pit));
        InstructionCounterState *ics = static_cast<InstructionCounterState *>(pb.getState(&ic, *pit));

        if (TerminatedPaths) {
            if (!tcs || !tcs->hasInputs()) {
                continue;
            }
        }

        statsFile << std::dec << *pit << "\t";

        if (tcs) {
            statsFile << "yes"
                      << "\t";
        } else {
            statsFile << "no"
                      << "\t";
        }

        if (!pfs) {
            statsFile << std::dec << "-"
                      << "\t";
            statsFile << std::dec << "-"
                      << "\t";
        } else {
            statsFile << std::dec << pfs->getPageFaults() << "\t";
            statsFile << pfs->getTlbMisses() << "\t";
        }

        if (!ics) {
            statsFile << std::dec << "-"
                      << "\t";
        } else {
            statsFile << std::dec << ics->getCount() << "\t";
        }

        statsFile << std::endl;
    }
}

void PfProfiler::process() {
    uint64_t maxMissCount = 0, maxMissPath = 0;
    uint64_t maxICount = 0, maxICountPath = 0;
    uint64_t minMissCount = (uint64_t) -1, minMissPath = 0;
    uint64_t minICount = (uint64_t) -1, minICountPath = 0;

    std::ofstream statsFile;
    statsFile.open(CpOutFile.c_str());

    if (TerminatedPaths) {
        statsFile << "#This report shows data for only those paths that generated a test case" << std::endl;
    }

    PathBuilder pb(&m_Parser);
    m_Parser.parse(m_FileName);

    ModuleCache mc(&pb);
    CacheProfiler cp(&mc, &pb);
    TestCase tc(&pb);
    InstructionCounter ic(&pb);

    pb.processTree();

    unsigned pathNum = 0;

    PathSet paths;
    pb.getPaths(paths);

    PathSet::iterator pit;
    for (pit = paths.begin(); pit != paths.end(); ++pit) {
        statsFile << "========== Path " << pathNum << " ========== " << std::endl;
        std::cout << std::dec << "Path " << pathNum << std::endl;

        TestCaseState *tcs = static_cast<TestCaseState *>(pb.getState(&tc, *pit));
        InstructionCounterState *ics = static_cast<InstructionCounterState *>(pb.getState(&ic, *pit));

        if (TerminatedPaths) {
            if (!tcs || !tcs->hasInputs()) {
                pathNum++;
                continue;
            }
        }

        if (ics) {
            ics->printCounter(statsFile);
        } else {
            statsFile << "No instruction count in the trace file for the current path" << std::endl;
        }

        if (tcs) {
            tcs->printInputs(statsFile);
        } else {
            statsFile << "No test case in the trace file for the current path" << std::endl;
        }

        TopMissesPerModule tmpm(&m_binaries, &cp);

        tmpm.setFilteredProcess(CPFilterProcess);
        tmpm.setFilteredModule(FilterModule);
        tmpm.setMinMissThreshold(CPMinMissCountFilter);

        tmpm.computeStats(*pit);
        statsFile << "Total misses on this path: " << std::dec << tmpm.getTotalMisses() << std::endl;

        tmpm.printAggregatedStatistics(statsFile);
        tmpm.print(statsFile);

        if (ics) {
            if (ics->getCount() > maxICount) {
                maxICount = ics->getCount();
                maxICountPath = pathNum;
            }

            if (ics->getCount() < minICount) {
                minICount = ics->getCount();
                minICountPath = pathNum;
            }
        }

        if (tmpm.getTotalMisses() > maxMissCount) {
            maxMissCount = tmpm.getTotalMisses();
            maxMissPath = pathNum;
        }

        if (tmpm.getTotalMisses() < minMissCount) {
            minMissCount = tmpm.getTotalMisses();
            minMissPath = pathNum;
        }

        ++pathNum;
        statsFile << std::endl;
    }

    statsFile << "----------------------------------" << std::endl << std::dec;
    statsFile << "Miss count        - Max:" << std::setw(10) << maxMissCount << " (path " << std::setw(10)
              << maxMissPath << ") ";
    statsFile << "Min:" << std::setw(10) << minMissCount << "(path " << std::setw(10) << minMissPath << ")"
              << std::endl;

    statsFile << "Instruction count - Max:" << std::setw(10) << maxICount << " (path " << std::setw(10) << maxICountPath
              << ") ";
    statsFile << "Min:" << std::setw(10) << minICount << "(path " << std::setw(10) << minICountPath << ")" << std::endl;

    return;
}
}

static std::vector<std::string> split(const std::string &s) {
    std::vector<std::string> ret;
    size_t p, prevp = 0;
    while ((p = s.find(' ')) != std::string::npos) {
        ret.push_back(s.substr(prevp, p));
        prevp = p;
    }
    return ret;
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " pfprofiler\n");
    std::cout << TraceFile << std::endl;

    ModList = split(ModListRaw);

    if (AnaType == "cache") {
        PfProfiler pf(TraceFile.getValue());
        pf.process();
    } else if (AnaType == "aggregated") {
        PfProfiler pf(TraceFile.getValue());
        pf.extractAggregatedData();
    } else {
        std::cout << "Unknown analysis type " << AnaType << std::endl;
    }

    return 0;
}

#ifdef afasfd
#warning Compiling with memory debugging support...

void *operator new(size_t s) {
    void *ret = malloc(s);
    if (!ret) {
        return NULL;
    }

    memset(ret, 0xAA, s);
    return ret;
}

void *operator new[](size_t s) {
    void *ret = malloc(s);
    if (!ret) {
        return NULL;
    }

    memset(ret, 0xAA, s);
    return ret;
}

void operator delete(void *pvMem) {
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
}

void operator delete[](void *pvMem) {
    size_t s = malloc_usable_size(pvMem);
    memset(pvMem, 0xBB, s);
    free(pvMem);
}

#endif
