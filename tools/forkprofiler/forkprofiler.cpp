///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#define __STDC_FORMAT_MACROS 1

#include <llvm/Support/CommandLine.h>

#include "lib/BinaryReaders/Library.h"
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

#include "forkprofiler.h"

using namespace llvm;
using namespace s2etools;

namespace {

cl::list<std::string> TraceFiles("trace", llvm::cl::value_desc("Input trace"), llvm::cl::Prefix,
                                 llvm::cl::desc("Specify an execution trace file"));

cl::opt<std::string> LogDir("outputdir", cl::desc("Store the coverage into the given folder"), cl::init("."));

cl::list<std::string> ModDir("moddir", cl::desc("Directory containing the binary modules"));
}

namespace s2etools {
ForkProfiler::ForkProfiler(Library *lib, ModuleCache *cache, LogEvents *events) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &ForkProfiler::onItem));
    m_cache = cache;
    m_library = lib;
}

ForkProfiler::~ForkProfiler() {
    m_connection.disconnect();
}

void ForkProfiler::doProfile(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                             const s2e::plugins::ExecutionTraceFork *te) {
    ModuleCacheState *mcs = static_cast<ModuleCacheState *>(m_events->getState(m_cache, &ModuleCacheState::factory));

    const ModuleInstance *mi = mcs->getInstance(hdr.pid, te->pc);

    ForkPoint fp;
    fp.pc = te->pc;
    fp.pid = hdr.pid;
    fp.count = 1;
    fp.line = 0;

    m_library->getInfo(mi, te->pc, fp.file, fp.line, fp.function);

    ForkPoints::iterator it = m_forkPoints.find(fp);
    if (it == m_forkPoints.end()) {
        if (mi) {
            fp.module = mi->Name;
            fp.loadbase = mi->LoadBase;
            fp.imagebase = mi->ImageBase;
        } else {
            fp.module = "";
            fp.loadbase = 0;
            fp.imagebase = 0;
        }
        m_forkPoints.insert(fp);
    } else {
        fp = *it;
        m_forkPoints.erase(*it);
        fp.count++;
        m_forkPoints.insert(fp);
    }
}

void ForkProfiler::doGraph(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                           const s2e::plugins::ExecutionTraceFork *te) {
    ModuleCacheState *mcs = static_cast<ModuleCacheState *>(m_events->getState(m_cache, &ModuleCacheState::factory));

    const ModuleInstance *mi = mcs->getInstance(hdr.pid, te->pc);

    Fork f;
    f.id = hdr.stateId;
    f.pid = hdr.pid;
    f.pc = te->pc;
    if (mi) {
        f.module = mi->Name;
        f.relPc = te->pc - mi->LoadBase + mi->ImageBase;
    } else {
        f.relPc = te->pc;
    }

    for (unsigned i = 0; i < te->stateCount; ++i) {
        f.children.push_back(te->children[i]);
    }

    m_forks.push_back(f);
}

void ForkProfiler::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type != s2e::plugins::TRACE_FORK) {
        return;
    }

    const s2e::plugins::ExecutionTraceFork *te = (const s2e::plugins::ExecutionTraceFork *) item;

    doProfile(hdr, te);
    doGraph(hdr, te);
}

static std::string getColor(unsigned val, unsigned maxval) {
    uint32_t index = val * 10 / maxval;
    uint32_t hexval = index * 128 / 10;
    char buf[32];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", hexval + 128, 0, 0);
    return buf;
}

void ForkProfiler::outputGraph(const std::string &path) const {
    std::stringstream ss;
    ss << path << "/"
       << "statetree.dot";
    std::ofstream tree(ss.str().c_str());

    std::map<uint32_t, uint32_t> stateIdMap;

    // Get the maximum count number, to compute a color scale
    ForkPoints::const_iterator fpit;
    uint32_t maxCount = 0;
    for (fpit = m_forkPoints.begin(); fpit != m_forkPoints.end(); ++fpit) {
        if ((*fpit).count > maxCount) {
            maxCount = (*fpit).count;
        }
    }

    tree << "digraph G {" << std::endl;

    ForkList::const_iterator it;
    for (it = m_forks.begin(); it != m_forks.end(); ++it) {
        const Fork &f = *it;
        uint32_t newId = stateIdMap[f.id];
        uint32_t density = 0;

        ForkPoint fp;
        fp.pc = f.pc;
        fp.pid = f.pid;
        fpit = m_forkPoints.find(fp);
        if (fpit != m_forkPoints.end()) {
            density = (*fpit).count;
        }

        tree << "s" << f.id << "_" << newId << " [label=\"" << std::hex << f.relPc << std::dec << "\" "
             << "style=filled fillcolor=\"" << getColor(density, maxCount) << "\"];"

             << std::endl;
        for (unsigned i = 0; i < f.children.size(); ++i) {
            uint32_t newChild = stateIdMap[f.children[i]] + 1;
            stateIdMap[f.children[i]] = newChild;

            tree << "s" << f.id << "_" << newId << "->"
                 << "s" << f.children[i] << "_" << newChild << ";" << std::endl;
        }
    }

    tree << "}" << std::endl;
}

void ForkProfiler::outputProfile(const std::string &path) const {
    std::stringstream ss;
    ss << path << "/"
       << "forkprofile.txt";
    std::ofstream forkProfile(ss.str().c_str());

    ForkPointsByCount fpCnt;

    ForkPoints::const_iterator it;
    for (it = m_forkPoints.begin(); it != m_forkPoints.end(); ++it) {
        fpCnt.insert(*it);
    }

    forkProfile << "#Pc      \tModule\tForkCnt\tSource\tFunction\tLine" << std::endl;

    ForkPointsByCount::const_iterator cit;
    for (cit = fpCnt.begin(); cit != fpCnt.end(); ++cit) {
        const ForkPoint &fp = *cit;
        forkProfile << std::hex << "0x" << std::setw(8) << std::setfill('0') << (fp.pc - fp.loadbase + fp.imagebase)
                    << "\t";
        forkProfile << std::setfill(' ');
        if (fp.module.size() > 0) {
            forkProfile << fp.module << "\t";
        } else {
            forkProfile << "?\t";
        }

        forkProfile << std::dec << fp.count << "\t";

        if (fp.file.size() > 0) {
            forkProfile << fp.file << "\t";
        } else {
            forkProfile << "?\t";
        }

        if (fp.function.size() > 0) {
            forkProfile << fp.function << "\t";
        } else {
            forkProfile << "?\t";
        }

        forkProfile << std::dec << fp.line << std::endl;
    }
}
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " debugger");

    Library library;
    library.setPaths(ModDir);

    LogParser parser;
    PathBuilder pb(&parser);
    parser.parse(TraceFiles);

    ModuleCache mc(&pb);
    ForkProfiler fp(&library, &mc, &pb);

    pb.processTree();

    fp.outputProfile(LogDir);
    fp.outputGraph(LogDir);

    return 0;
}
