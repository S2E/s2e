///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_TBTRACE_H
#define S2ETOOLS_TBTRACE_H

#include "lib/ExecutionTracer/LogParser.h"

#include <fstream>
#include <ostream>

#include "lib/BinaryReaders/Library.h"
#include "lib/Utils/BasicBlockListParser.h"

namespace s2etools {

class ModuleCache;

class TbTrace {
public:
    // One program counter can have multiple lines of assembly code
    typedef std::vector<std::string> DisassemblyEntry;

    // Collects the entire assembly listing for a module
    typedef std::map<uint64_t, DisassemblyEntry> ModuleDisassembly;

    typedef std::map<std::string, ModuleDisassembly> Disassembly;

    // Convenient definition of basic blocks
    typedef BasicBlockListParser::BasicBlocks TbTraceBbs;

    // Gathers all the basic blocks contained in a module
    typedef std::map<std::string, TbTraceBbs> ModuleBasicBlocks;

private:
    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;
    Disassembly m_disassembly;
    ModuleBasicBlocks m_basicBlocks;
    std::ofstream &m_output;

    sigc::connection m_connection;

    bool m_hasItems;
    bool m_hasModuleInfo;
    bool m_hasDebugInfo;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    bool parseDisassembly(const std::string &listingFile, Disassembly &out);
    void printDisassembly(const std::string &module, uint64_t relPc, unsigned tbSize);

    void printDebugInfo(uint64_t pid, uint64_t pc, unsigned tbSize, bool printListing);

    template <typename T>
    void printRegisters(const char *regs[], const uint64_t *values, uint8_t symbMask, unsigned count,
                        unsigned breakIndex);
    void printRegisters(const s2e::plugins::ExecutionTraceTb *te);
    void printRegisters64(const s2e::plugins::ExecutionTraceTb64 *te);
    void printMemoryChecker(const s2e::plugins::ExecutionTraceMemChecker::Serialized *item);

public:
    TbTrace(Library *lib, ModuleCache *cache, LogEvents *events, std::ofstream &ofs);
    virtual ~TbTrace();

    void outputTraces(const std::string &Path) const;
    bool hasItems() const {
        return m_hasItems;
    }

    bool hasModuleInfo() const {
        return m_hasModuleInfo;
    }

    bool hasDebugInfo() const {
        return m_hasDebugInfo;
    }
};

class TbTraceTool {
private:
    LogParser m_parser;

    Library m_binaries;

public:
    TbTraceTool();
    ~TbTraceTool();

    void process();
    void flatTrace();
};
}

#endif
