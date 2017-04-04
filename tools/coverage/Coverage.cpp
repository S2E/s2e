///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

//#define __STDC_CONSTANT_MACROS 1
//#define __STDC_LIMIT_MACROS 1
#define __STDC_FORMAT_MACROS 1

#include <llvm/ADT/SmallString.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Path.h>

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

#include "Coverage.h"

using namespace llvm;
using namespace s2etools;

namespace {

cl::list<std::string> TraceFiles("trace", llvm::cl::value_desc("Input trace"), llvm::cl::Prefix,
                                 llvm::cl::desc("Specify an execution trace file"));

cl::opt<std::string> LogDir("outputdir", cl::desc("Store the coverage into the given folder"), cl::init("."));

cl::list<std::string> ModDir(
    "moddir",
    cl::desc("Directory containing binary modules, the basic block list (*.bblist), exclude file (*.excl), etc."));

cl::opt<bool> Compact("compact", cl::desc("Do not display non-covered blocks"), cl::init(false));

// cl::opt<std::string>
//    CovType("covtype", cl::desc("Coverage type"), cl::init("basicblock"));
}

namespace s2etools {
BasicBlockCoverage::BasicBlockCoverage(const std::string &moduleDir, const std::string &moduleName) {
    llvm::SmallString<128> basicBlockListFile(moduleDir);
    llvm::sys::path::append(basicBlockListFile, moduleName);
    llvm::sys::path::replace_extension(basicBlockListFile, "bblist");

    FILE *fp = fopen(basicBlockListFile.c_str(), "r");
    if (!fp) {
        std::cerr << "Could not open file " << basicBlockListFile.c_str() << std::endl;
        return;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp)) {
        uint64_t start, end;
        char name[512];
        sscanf(buffer, "0x%" PRIx64 " 0x%" PRIx64 " %[^\r\t\n]s", &start, &end, name);
        // std::cout << "Read 0x" << std::hex << start << " 0x" << end << " " << name << std::endl;

        unsigned prevCount = m_allBbs.size();
        std::pair<BasicBlocks::iterator, bool> result = m_allBbs.insert(BasicBlock(start, end));
        if (!result.second) {
            std::cout << "Won't insert this block : existing block: " << (*result.first).start << std::endl;
            continue;
        }

        BasicBlocks &bbs = m_functions[name];
        // XXX: the +1 is here to compensate the broken extraction script, which
        // does not take into account the whole size of the last instruction.
        prevCount = bbs.size();
        bbs.insert(BasicBlock(start, end));
        assert(prevCount == bbs.size() - 1);
    }

    Functions::iterator fit;
    unsigned fcnBbCount = 0;
    for (fit = m_functions.begin(); fit != m_functions.end(); ++fit) {
        fcnBbCount += (*fit).second.size();
    }
    assert(fcnBbCount == m_allBbs.size());

    if (m_allBbs.size() == 0) {
        std::cerr << "No basic blocks found in the list for " << moduleName << ". Check the format of the file."
                  << std::endl;
    }

    parseExcludeFile(moduleDir, moduleName);
}

void BasicBlockCoverage::parseExcludeFile(const std::string &moduleDir, const std::string &moduleName) {
    llvm::SmallString<128> excludeFileName(moduleDir);
    llvm::sys::path::append(excludeFileName, moduleName);
    llvm::sys::path::replace_extension(excludeFileName, "excl");

    FILE *fp = fopen(excludeFileName.c_str(), "r");
    if (!fp) {
        std::cerr << "Could not open file " << excludeFileName.c_str() << std::endl;
        return;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp)) {
        char name[512];
        sscanf(buffer, "%[^\r\t\n]s", name);
        m_ignoredFunctions.insert(std::string(name));
    }

    fclose(fp);
}

// Start and end must be local to the model
bool BasicBlockCoverage::addTranslationBlock(uint64_t ts, uint64_t start, uint64_t end) {
    Block tb(ts, start, end);
    Blocks::iterator it = m_uniqueTbs.find(tb);

    if (it == m_uniqueTbs.end()) {
        m_uniqueTbs.insert(tb);
        return true;
    } else {
        if ((*it).timeStamp > ts) {
            m_uniqueTbs.erase(*it);
            m_uniqueTbs.insert(tb);
            return true;
        }
    }

    return false;
}

void BasicBlockCoverage::convertTbToBb() {
    BasicBlocks::iterator it;
    Blocks::iterator tbit;

    for (tbit = m_uniqueTbs.begin(); tbit != m_uniqueTbs.end(); ++tbit) {
        const Block &tb = *tbit;

        for (uint64_t s = tb.start; s < tb.end; s++) {

            BasicBlock tbb(s, s + 1);
            it = m_allBbs.find(tbb);
            if (it == m_allBbs.end()) {
                std::cerr << "Missing TB: " << std::hex << "0x" << tb.start << ":0x" << tb.end << std::endl;
                continue;
            }
            // assert(it != m_allBbs.end());

            BasicBlock newBlock;
            newBlock.timeStamp = tb.timeStamp;
            newBlock.start = (*it).start;
            newBlock.end = (*it).end;

            if (m_coveredBbs.find(newBlock) == m_coveredBbs.end()) {
                m_coveredBbs.insert(newBlock);
            }
        }
    }
}

void BasicBlockCoverage::printTimeCoverage(std::ostream &os) const {
    BlocksByTime bbtime;
    BlocksByTime::const_iterator tit;

    bool timeInited = false;
    uint64_t firstTime = 0;

    BasicBlocks::const_iterator it;
    for (it = m_coveredBbs.begin(); it != m_coveredBbs.end(); ++it) {
        bbtime.insert(*it);
    }

    unsigned i = 0;
    for (tit = bbtime.begin(); tit != bbtime.end(); ++tit) {
        const BasicBlock &b = *tit;

        if (!timeInited) {
            firstTime = b.timeStamp;
            timeInited = true;
        }

        // DO NOT TOUCH THE FORMAT, USED BY SCRIPTS TO BUILD THE PAPER
        os << std::dec << (b.timeStamp - firstTime) / 1000000              // Timestamp
           << std::dec << " " << i << " "                                  // Cumulative block count
           << std::hex << " 0x" << b.start << " 0x" << b.end << std::endl; // Addresses
        ++i;
    }
}

// Returns the time in seconds of the last covered block
uint64_t BasicBlockCoverage::getTimeCoverage() const {
    BlocksByTime bbtime;
    BlocksByTime::const_iterator tfirst;
    BlocksByTime::const_reverse_iterator tit;

    BasicBlocks::const_iterator it;
    for (it = m_coveredBbs.begin(); it != m_coveredBbs.end(); ++it) {
        bbtime.insert(*it);
    }

    tfirst = bbtime.begin();
    tit = bbtime.rbegin();

    return ((*tit).timeStamp - (*tfirst).timeStamp) / 1000000;
}

void BasicBlockCoverage::printReport(std::ostream &os, uint64_t pathCount, bool useIgnoreList, bool csv) const {
    unsigned touchedFunctions = 0;
    unsigned fullyCoveredFunctions = 0;
    unsigned touchedFunctionsBb = 0;
    unsigned touchedFunctionsTotalBb = 0;
    unsigned allFunctionsBb = 0;
    Functions::const_iterator fit;

    for (fit = m_functions.begin(); fit != m_functions.end(); ++fit) {
        if (useIgnoreList) {
            if (m_ignoredFunctions.find((*fit).first) != m_ignoredFunctions.end()) {
                continue;
            }
        }

        const BasicBlocks &fcnbb = (*fit).second;
        BasicBlocks uncovered;
        BasicBlocks::const_iterator bbit;
        for (bbit = fcnbb.begin(); bbit != fcnbb.end(); ++bbit) {
            if (m_coveredBbs.find(*bbit) == m_coveredBbs.end()) {
                uncovered.insert(*bbit);
            }
        }

        unsigned int coveredCount = (fcnbb.size() - uncovered.size());
        char line[512];

        if (csv) {
            snprintf(line, sizeof(line), "%u,%u,%u,%s,", (unsigned) (coveredCount * 100 / fcnbb.size()), coveredCount,
                     (unsigned) fcnbb.size(), (*fit).first.c_str());
        } else {
            snprintf(line, sizeof(line), "(%3u%%) %03u/%03u %-50s ", (unsigned) (coveredCount * 100 / fcnbb.size()),
                     coveredCount, (unsigned) fcnbb.size(), (*fit).first.c_str());
        }

        os << line;

        if (uncovered.size() == fcnbb.size()) {
            os << "The function was not exercised";
        } else {
            if (uncovered.size() == 0) {
                os << "Full coverage";
                fullyCoveredFunctions++;
            } else {
                if (!Compact) {
                    char delim = csv ? ',' : ' ';
                    for (bbit = uncovered.begin(); bbit != uncovered.end(); ++bbit) {
                        os << std::hex << "0x" << (*bbit).start << delim;
                    }
                }
            }
            touchedFunctionsBb += coveredCount;
            touchedFunctionsTotalBb += fcnbb.size();
            touchedFunctions++;
        }

        allFunctionsBb += fcnbb.size();

        os << std::endl;
    }
    os << std::endl;

    if (useIgnoreList) {
        os << "Basic block coverage:    " << std::dec << touchedFunctionsBb << "/" << allFunctionsBb << "("
           << (touchedFunctionsBb * 100 / allFunctionsBb) << "%)" << std::endl;

    } else {
        os << "Basic block coverage:    " << std::dec << m_coveredBbs.size() << "/" << m_allBbs.size() << "("
           << (m_coveredBbs.size() * 100 / m_allBbs.size()) << "%)" << std::endl;

        os << "Function block coverage: " << std::dec << touchedFunctionsBb << "/" << touchedFunctionsTotalBb << "("
           << (touchedFunctionsBb * 100 / touchedFunctionsTotalBb) << "%)" << std::endl;
    }

    if (useIgnoreList) {
        os << "Fully covered functions: " << std::dec << fullyCoveredFunctions << "/" << touchedFunctions << "("
           << (fullyCoveredFunctions * 100 / touchedFunctions) << "%)" << std::endl;
    } else {
        os << "Total touched functions: " << std::dec << touchedFunctions << "/" << m_functions.size() << "("
           << (touchedFunctions * 100 / m_functions.size()) << "%)" << std::endl;

        os << "Fully covered functions: " << std::dec << fullyCoveredFunctions << "/" << m_functions.size() << "("
           << (fullyCoveredFunctions * 100 / m_functions.size()) << "%)" << std::endl;
    }

    os << "Time to cover last block: " << std::dec << getTimeCoverage() << std::endl;
    os << "# paths:                  " << std::dec << pathCount << std::endl;
}

void BasicBlockCoverage::printBBCov(std::ostream &os) const {
    Functions::const_iterator fit;

    for (fit = m_functions.begin(); fit != m_functions.end(); ++fit) {
        const BasicBlocks &fcnbb = (*fit).second;
        BasicBlocks uncovered;
        BasicBlocks::const_iterator bbit;
        for (bbit = fcnbb.begin(); bbit != fcnbb.end(); ++bbit) {
            Block b(0, (*bbit).start, 0);
            if (m_uniqueTbs.find(b) == m_uniqueTbs.end())
                os << std::setw(0) << "-";
            else
                os << std::setw(0) << "+";

            os << std::hex << "0x" << std::setfill('0') << std::setw(8) << (*bbit).start << std::setw(0) << ":0x"
               << std::setw(8) << (*bbit).end << std::endl;
        }
        os << std::endl;
    }
}

Coverage::Coverage(Library *lib, ModuleCache *cache, LogEvents *events) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &Coverage::onItem));
    m_cache = cache;
    m_library = lib;
    m_pathCount = 1;
    m_unknownModuleCount = 0;
}

Coverage::~Coverage() {
    m_connection.disconnect();

    BbCoverageMap::iterator it;
    for (it = m_bbCov.begin(); it != m_bbCov.end(); ++it) {
        delete (*it).second;
    }
}

BasicBlockCoverage *Coverage::loadCoverage(const ModuleInstance *mi) {
    BasicBlockCoverage *bbcov = NULL;
    assert(mi);

    BbCoverageMap::iterator it = m_bbCov.find(mi->Name);
    if (it == m_bbCov.end()) {
        // Look for the file containing the bbs.
        std::string path;
        if (m_library->findLibrary(mi->Name, path)) {
            llvm::SmallString<128> modPath(path);
            llvm::sys::path::remove_filename(modPath);
            BasicBlockCoverage *bb = new BasicBlockCoverage(modPath.str(), mi->Name);
            m_bbCov[mi->Name] = bb;
            bbcov = bb;
        } else {
            m_notFoundModuleImages.insert(mi->Name);
        }
    } else {
        bbcov = (*it).second;
    }

    return bbcov;
}

void Coverage::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type == s2e::plugins::TRACE_FORK) {
        s2e::plugins::ExecutionTraceFork *f = (s2e::plugins::ExecutionTraceFork *) item;
        m_pathCount += f->stateCount - 1;
    }

    if (hdr.type != s2e::plugins::TRACE_TB_START) {
        return;
    }

    const s2e::plugins::ExecutionTraceTb *te = (const s2e::plugins::ExecutionTraceTb *) item;

    ModuleCacheState *mcs = static_cast<ModuleCacheState *>(m_events->getState(m_cache, &ModuleCacheState::factory));

    const ModuleInstance *mi = mcs->getInstance(hdr.pid, te->pc);
    if (!mi) {
        ++m_unknownModuleCount;
        return;
    }

    BasicBlockCoverage *bbcov = loadCoverage(mi);
    if (!bbcov) {
        return;
    }

    uint64_t relPc = te->pc - mi->LoadBase + mi->ImageBase;

    bbcov->addTranslationBlock(hdr.timeStamp, relPc, relPc + te->size - 1);
}

void Coverage::outputCoverage(const std::string &path) const {
    BbCoverageMap::const_iterator it;

    for (it = m_bbCov.begin(); it != m_bbCov.end(); ++it) {
        std::stringstream ss;
        ss << path << "/" << (*it).first << ".timecov";
        std::ofstream timecov(ss.str().c_str());

        (*it).second->convertTbToBb();
        (*it).second->printTimeCoverage(timecov);

        std::stringstream ss1;
        ss1 << path << "/" << (*it).first << ".repcov";
        std::ofstream report(ss1.str().c_str());
        (*it).second->printReport(report, m_pathCount);

        if ((*it).second->hasIgnoredFunctions() > 0) {
            std::stringstream ss11;
            ss11 << path << "/" << (*it).first << ".repcov-filtered";
            std::ofstream report(ss11.str().c_str());
            (*it).second->printReport(report, m_pathCount, true);

            std::stringstream ss12;
            ss12 << path << "/" << (*it).first << ".repcov-filtered.csv";
            std::ofstream reportcsv(ss12.str().c_str());
            (*it).second->printReport(reportcsv, m_pathCount, true, true);
        }

        std::stringstream ss2;
        ss2 << path << "/" << (*it).first << ".bbcov";
        std::ofstream bbcov(ss2.str().c_str());
        (*it).second->printBBCov(bbcov);
    }
}

void Coverage::printErrors() const {
    if (m_unknownModuleCount) {
        std::cerr << "There were " << m_unknownModuleCount << " trace entries whose "
                  << "program counter was not in any known module.\n"
                  << "Make sure you enabled ModuleTracer in the S2E configuration file\n";
    }

    if (m_notFoundModuleImages.size() > 0) {
        std::cerr << "Could not find executable images of the following modules.\n"
                  << "Please check your module path settings.\n";

        std::set<std::string>::const_iterator it;
        for (it = m_notFoundModuleImages.begin(); it != m_notFoundModuleImages.end(); ++it) {
            std::cerr << *it << "\n";
        }
    }
}

CoverageTool::CoverageTool() {
    m_binaries.setPaths(ModDir);
}

CoverageTool::~CoverageTool() {
}

void CoverageTool::flatTrace() {
    PathBuilder pb(&m_parser);
    m_parser.parse(TraceFiles);

    ModuleCache mc(&pb);
    Coverage cov(&m_binaries, &mc, &pb);

    pb.processTree();
    cov.printErrors();

    cov.outputCoverage(LogDir);
}
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " coverage");

    s2etools::CoverageTool cov;

    cov.flatTrace();

    return 0;
}
