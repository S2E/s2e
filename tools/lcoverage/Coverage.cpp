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
 *
 * Currently maintained by:
 *    Damien Engels <dengels@cisco.com>
 *
 */

#define __STDC_FORMAT_MACROS 1

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Path.h>

#include "lib/ExecutionTracer/ModuleParser.h"
#include "lib/ExecutionTracer/Path.h"
#include "lib/ExecutionTracer/TestCase.h"

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>

#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/Triple.h>
#include <llvm/DebugInfo/DIContext.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/RelocVisitor.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/MemoryObject.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstring>
#include <list>
#include <string>

#include <fstream>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdio.h>
#include "Coverage.h"

using namespace llvm;
using namespace llvm::object;
using namespace s2etools;

namespace {

cl::list<std::string> TraceFiles("trace", llvm::cl::value_desc("Input trace"), llvm::cl::Prefix,
                                 llvm::cl::desc("Specify an execution trace file"));

cl::opt<std::string> LogDir("outputdir", cl::desc("Store the coverage into the given folder"), cl::init("."));

cl::list<std::string> ModDir("moddir", cl::desc("Directory containing binary modules"));
}

namespace s2etools {

/* Adds a line associated with a range of addresses to the module returns false
 * if that line has already been reported for the same range */
bool SourceFile::addExecutableLine(const ModuleCoverage *m, uint64_t line_nb, uint64_t start, uint64_t end) {
    Line l(line_nb, start, end, m->isCovered(start, end));

    Lines::iterator it = executableLines.find(l);

    if (it == executableLines.end()) {
        executableLines.insert(l);
        return true;
    }

    return false;
}

void SourceFile::printReport(std::ostream &os) const {

    Lines::const_iterator lit;
    char line[256];

    /* Simple character separated records */
    for (lit = executableLines.begin(); lit != executableLines.end(); ++lit) {
        snprintf(line, sizeof(line), "%s:%lu:%u", f_path.c_str(), lit->line_nb, lit->covered ? 1 : 0);

        os << line << std::endl;
    }
}

/* Format readable by lcov tools such as genhtml */
void SourceFile::printLcovReport(std::ostream &os) const {

    Lines::const_iterator lit;

    if (f_path == "<invalid>") {
        return;
    }

    os << "TN:" << std::endl;
    os << "SF:" << f_path << std::endl;

    for (lit = executableLines.begin(); lit != executableLines.end(); ++lit) {
        os << "DA:" << lit->line_nb << "," << (lit->covered ? 1 : 0) << std::endl;
    }

    os << "end_of_record" << std::endl;
}

ModuleCoverage::ModuleCoverage(const ModuleInstance *mi, const std::string &moduleDir, const std::string &moduleName) {
    m_instance = mi;
    m_name = moduleName;
    m_dir = moduleDir;
}

/* Checks for a block overlapping with this range */
bool ModuleCoverage::isCovered(uint64_t start, uint64_t end) const {
    return coveredBlocks.find(Block(start, end)) != coveredBlocks.end();
}

// Start and end must be local to the model
void ModuleCoverage::addTranslationBlock(uint64_t start, uint64_t end) {
    if (start > end) {
        std::cerr << "Bad translation block : start = 0x" << std::hex << start << ", end = 0x" << end << "\n";
        return;
    }
    Block tb(start, end);
    Blocks::iterator it = coveredBlocks.find(tb);

    if (it == coveredBlocks.end()) {
        coveredBlocks.insert(tb);
    } else {
        /* If the block overlaps with another
         * existing block split what's left
         * and insert it */
        if (it->end < end) {
            addTranslationBlock(it->end + 1, end);
        }

        if (it->start > start) {
            addTranslationBlock(start, it->start - 1);
        }
    }
}

bool ModuleCoverage::addExecutableLine(const std::string &path, uint64_t line_nb, uint64_t start, uint64_t end) {
    SourceFile *s_file = NULL;

    FileMap::iterator it = sources.find(path);
    if (it == sources.end()) {
        s_file = new SourceFile(path);
        sources[path] = s_file;
    } else {
        s_file = (*it).second;
    }

    return s_file->addExecutableLine(this, line_nb, start, end);
}

void ModuleCoverage::computeCoverageDwarf() {
    llvm::SmallString<128> modulePath(m_dir);
    llvm::sys::path::append(modulePath, m_name);

    llvm::outs() << "Computing coverage for " << modulePath.str() << " [using LLVM DWARF]\n";

    auto ErrorOrMemBuff = MemoryBuffer::getFileOrSTDIN(modulePath);

    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        llvm::errs() << modulePath.str() << ": " << EC.message() << '\n';
        return;
    }

    Expected<std::unique_ptr<ObjectFile>> Obj(ObjectFile::createObjectFile(ErrorOrMemBuff.get()->getMemBufferRef()));
    if (!Obj) {
        llvm::errs() << modulePath.str() << ": Unable to create object file\n";
    }

    DWARFContextInMemory dictx(*Obj->get());

    // Adapted from llvm::DWARFContext::dump
    std::vector<uint64_t> addresses;
    for (const auto &CU : dictx.compile_units()) {
        const auto *CUDIE = CU->getUnitDIE();
        if (CUDIE == nullptr) {
            continue;
        }

        unsigned stmtOffset = CUDIE->getAttributeValueAsSectionOffset(CU.get(), dwarf::DW_AT_stmt_list, -1U);
        if (stmtOffset != -1U) {
            addresses.push_back(stmtOffset);
        }
    }

    if (addresses.size() > 0) {
        for (unsigned i = 0; i < addresses.size() - 1; ++i) {
            uint64_t address = addresses[i];
            uint64_t next = addresses[i + 1];
            assert(address < next);

            DILineInfo dli = dictx.getLineInfoForAddress(address);

            std::string f = std::string(!dli.FileName.empty() ? dli.FileName : "<unknown>");
            addExecutableLine(f, dli.Line, address, next - 1);
        }
    } else {
        std::cout << "Did not find any address\n";
    }
}

void ModuleCoverage::computeCoverage() {
    std::cout << "Computing coverage for " << m_name << "\n";

    llvm::SmallString<128> lineInfo(m_dir);
    llvm::sys::path::append(lineInfo, m_name);
    llvm::sys::path::replace_extension(lineInfo, "lines");

    FILE *fp = fopen(lineInfo.c_str(), "r");

    if (!fp) {
        llvm::errs() << "Could not open file " << lineInfo.str() << ", trying LLVM DWARF parser\n";
        computeCoverageDwarf();
        return;
    }

    char buffer[512];

    int count = 0;
    uint64_t last = 0, last_line = 0;
    std::string last_file = "";
    while (fgets(buffer, sizeof(buffer), fp)) {
        uint64_t line, addr;
        char path[512];

        ++count;

        // XXX: use MACRO to have right format
        sscanf(buffer, "%lu %lx %[^\r\t\n]s", &line, &addr, path);

        if (last != 0) {
            // XXX : (hack)
            // dwarfdump sometimes outputs addresses out of order
            uint64_t end = (addr <= last) ? last : (addr - 1);

            addExecutableLine(last_file, last_line, last, end);
        }

        last_file = std::string(path);
        last = addr;
        last_line = line;
    }

    fclose(fp);

    std::cout << " => processed " << std::dec << count << " lines" << std::endl;
}

void ModuleCoverage::printLineCoverage(std::ostream &osNormal, std::ostream &osLcov) const {
    FileMap::const_iterator fit;

    for (fit = sources.begin(); fit != sources.end(); ++fit) {
        const SourceFile *file = (*fit).second;

        file->printReport(osNormal);
        file->printLcovReport(osLcov);
    }
}

Coverage::Coverage(Library *lib, ModuleCache *cache, LogEvents *events) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &Coverage::onItem));
    m_cache = cache;
    m_library = lib;
    m_unknownModuleCount = 0;
}

Coverage::~Coverage() {
    m_connection.disconnect();

    ModuleCoverageMap::iterator it;
    for (it = m_bCov.begin(); it != m_bCov.end(); ++it) {
        delete (*it).second;
    }
}

ModuleCoverage *Coverage::loadCoverage(const ModuleInstance *mi) {
    ModuleCoverage *bbcov = NULL;
    assert(mi);

    if (m_notFoundModuleImages.find(mi->Name) != m_notFoundModuleImages.end()) {
        return NULL;
    }

    ModuleCoverageMap::iterator it = m_bCov.find(mi->Name);
    if (it == m_bCov.end()) {

        std::string path;
        if (m_library->findLibrary(mi->Name, path)) {
            llvm::SmallString<128> modPath(path);
            llvm::sys::path::remove_filename(modPath);
            ModuleCoverage *bb = new ModuleCoverage(mi, modPath.str(), mi->Name);
            m_bCov[mi->Name] = bb;
            bbcov = bb;
        } else {
            std::cout << "Couldn't find module " << mi->Name << std::endl;
            m_notFoundModuleImages.insert(mi->Name);
        }
    } else {
        bbcov = (*it).second;
    }

    return bbcov;
}

void Coverage::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {

    if (hdr.type != s2e::plugins::TRACE_BLOCK) {
        return;
    }

    const s2e::plugins::ExecutionTraceBlock *block = (const s2e::plugins::ExecutionTraceBlock *) item;

    ModuleCacheState *mcs = static_cast<ModuleCacheState *>(m_events->getState(m_cache, &ModuleCacheState::factory));

    const ModuleInstance *mi = mcs->getInstance(hdr.pid, block->startPc);
    if (!mi) {
        ++m_unknownModuleCount;
        return;
    }

    ModuleCoverage *bbcov = loadCoverage(mi);
    if (!bbcov) {
        /* Not found module image */
        return;
    }

    uint64_t relStart = block->startPc - mi->LoadBase + mi->ImageBase;
    uint64_t relEnd = block->endPc - mi->LoadBase + mi->ImageBase;

    bbcov->addTranslationBlock(relStart, relEnd);
}

void Coverage::outputCoverage(const std::string &path) const {
    ModuleCoverageMap::const_iterator it;

    for (it = m_bCov.begin(); it != m_bCov.end(); ++it) {
        (*it).second->computeCoverage();

        std::stringstream ss;
        ss << path << "/" << (*it).first << ".linecov";
        std::ofstream linecov(ss.str().c_str());

        std::stringstream ss1;
        ss1 << path << "/" << (*it).first << ".info";
        std::ofstream lcov(ss1.str().c_str());

        (*it).second->printLineCoverage(linecov, lcov);
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
    cl::ParseCommandLineOptions(argc, (char **) argv, " coverage2");

    s2etools::CoverageTool cov;

    cov.flatTrace();

    return 0;
}
