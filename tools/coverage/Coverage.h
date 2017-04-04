///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_COVERAGE_H
#define S2ETOOLS_COVERAGE_H

#include "lib/BinaryReaders/Library.h"

#include <inttypes.h>
#include <map>
#include <set>
#include <string>

namespace s2etools {

struct BasicBlock {
    uint64_t timeStamp;
    uint64_t start;
    uint64_t end;
    bool operator()(const BasicBlock &b1, const BasicBlock &b2) const {
        return b1.end < b2.start;
    }

    BasicBlock(uint64_t s, uint64_t e) {
        start = s;
        end = e;
        timeStamp = 0;
    }

    BasicBlock() {
        timeStamp = 0;
        start = end = 0;
    }

    struct SortByTime {

        bool operator()(const BasicBlock &b1, const BasicBlock &b2) const {
            if (b1.timeStamp < b2.timeStamp) {
                return true;
            }
            return b1.start < b2.start;
        }
    };
};

// Either a BB or TB depending on the context
struct Block {
    uint64_t timeStamp;
    uint64_t start;
    uint64_t end;

    bool operator()(const Block &b1, const Block &b2) const {
        return b1.start < b2.start;
    }

    Block() {
        timeStamp = start = end = 0;
    }

    Block(uint64_t ts, uint64_t s, uint64_t e) {
        timeStamp = ts;
        start = s;
        end = e;
    }
};

class BasicBlockCoverage {
public:
    typedef std::set<BasicBlock, BasicBlock> BasicBlocks;
    typedef std::set<Block, Block> Blocks;
    typedef std::set<BasicBlock, BasicBlock::SortByTime> BlocksByTime;
    typedef std::map<std::string, BasicBlocks> Functions;

    typedef std::set<std::string> FunctionNames;

private:
    std::string m_name;
    BasicBlocks m_allBbs;
    BasicBlocks m_coveredBbs;
    Functions m_functions;

    Functions m_coveredFunctions;
    FunctionNames m_ignoredFunctions;
    Blocks m_uniqueTbs;

public:
    BasicBlockCoverage(const std::string &moduleDir, const std::string &moduleName);

    void parseExcludeFile(const std::string &moduleDir, const std::string &moduleName);

    // Start and end must be local to the module
    // Returns true if the added block resulted in covering new basic blocks
    bool addTranslationBlock(uint64_t ts, uint64_t start, uint64_t end);
    uint64_t getTimeCoverage() const;
    void convertTbToBb();
    void printTimeCoverage(std::ostream &os) const;
    void printReport(std::ostream &os, uint64_t pathCount, bool useIgnoreList = false, bool csv = false) const;
    void printBBCov(std::ostream &os) const;

    bool hasIgnoredFunctions() const {
        return m_ignoredFunctions.size() > 0;
    }
};

class Coverage {
public:
private:
    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;
    uint64_t m_pathCount;

    typedef std::map<std::string, BasicBlockCoverage *> BbCoverageMap;
    BbCoverageMap m_bbCov;

    /* Occurrence count of program counters not in any known module */
    uint64_t m_unknownModuleCount;

    /* Module names for which the tool could not find the executable image. */
    std::set<std::string> m_notFoundModuleImages;

    /* BB lists that were not found. */
    std::set<std::string> m_notFoundBbList;

    BasicBlockCoverage *loadCoverage(const ModuleInstance *mi);

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    Coverage(Library *lib, ModuleCache *cache, LogEvents *events);
    virtual ~Coverage();

    void outputCoverage(const std::string &Path) const;

    uint64_t getPathCount() const {
        return m_pathCount;
    }

    void printErrors() const;
};

class CoverageTool {
private:
    LogParser m_parser;

    Library m_binaries;

public:
    CoverageTool();
    ~CoverageTool();

    void process();
    void flatTrace();
};
}

#endif
