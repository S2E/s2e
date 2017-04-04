///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Cisco Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Cisco Systems nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CISCO SYSTEMS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef S2ETOOLS_COVERAGE_H
#define S2ETOOLS_COVERAGE_H

#include <inttypes.h>
#include <map>
#include <set>
#include <string>

#include "lib/BinaryReaders/Library.h"

namespace s2etools {

/* Translation Block */
struct Block {
    uint64_t start;
    uint64_t end;

    bool operator()(const Block &b1, const Block &b2) const {
        return b1.end < b2.start; /* Strictly no overlapping blocks */
    }

    Block() {
        start = end = 0;
    }

    Block(uint64_t s, uint64_t e) {
        assert(s <= e);
        start = s;
        end = e;
    }
};

/* Executable Line with corresponding range of addresses*/
struct Line {
    uint64_t line_nb;
    uint64_t start_addr;
    uint64_t end_addr;
    bool covered;

    bool operator()(const Line &l1, const Line &l2) const {
        if (l1.line_nb == l2.line_nb) {
            if (l1.start_addr == l2.start_addr) {
                return l1.end_addr < l2.end_addr;
            }
            return l1.start_addr < l2.start_addr;
        }
        return l1.line_nb < l2.line_nb;
    }

    Line() {
        line_nb = start_addr = end_addr = 0;
        covered = false;
    }

    Line(uint64_t l, uint64_t s, uint64_t e, bool c) {
        assert(s <= e);
        line_nb = l;
        start_addr = s;
        end_addr = e;
        covered = c;
    }
};

class ModuleCoverage;

/* Line information of sources files compiled into modules */
class SourceFile {
public:
    typedef std::set<Line, Line> Lines;

private:
    std::string f_path;

    Lines executableLines;

public:
    SourceFile(const std::string &path) {
        f_path = path;
    }

    /* Add debug info for a line (local to a module) */
    bool addExecutableLine(const ModuleCoverage *m, uint64_t line_nb, uint64_t start, uint64_t end);

    /* Print report of line coverage information */
    void printReport(std::ostream &os) const;

    /* Prints the report in format that can be used by tools such as genhtml */
    void printLcovReport(std::ostream &os) const;
};

class ModuleCoverage {
public:
    typedef std::set<Block, Block> Blocks;
    typedef std::map<std::string, SourceFile *> FileMap;

private:
    std::string m_name;
    std::string m_dir;

    const ModuleInstance *m_instance;

    Blocks coveredBlocks;
    FileMap sources;

public:
    ModuleCoverage(const ModuleInstance *mi, const std::string &moduleDir, const std::string &moduleName);

    /* Checks if any address in the range has been touched by execution */
    bool isCovered(uint64_t start, uint64_t end) const;

    void addTranslationBlock(uint64_t start, uint64_t end);

    /* Call only after all blocks have been added */
    bool addExecutableLine(const std::string &path, uint64_t line_nb, uint64_t start, uint64_t end);

    void computeCoverageDwarf();
    void computeCoverage();

    /* Print report of line coverage information */
    void printLineCoverage(std::ostream &osNormal, std::ostream &osLcov) const;
};

class Coverage {
public:
private:
    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;

    typedef std::map<std::string, ModuleCoverage *> ModuleCoverageMap;
    ModuleCoverageMap m_bCov;

    /* Occurrence count of program counters not in any known module */
    uint64_t m_unknownModuleCount;

    /* Module names for which the tool could not find the executable image. */
    std::set<std::string> m_notFoundModuleImages;

    ModuleCoverage *loadCoverage(const ModuleInstance *mi);

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    Coverage(Library *lib, ModuleCache *cache, LogEvents *events);
    virtual ~Coverage();

    void outputCoverage(const std::string &Path) const;

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
