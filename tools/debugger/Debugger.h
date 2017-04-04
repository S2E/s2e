///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_DEBUGGER_H
#define S2ETOOLS_DEBUGGER_H

#include "lib/BinaryReaders/Library.h"

namespace s2etools {

class ExecutionDebugger {
private:
    std::ostream &m_os;

    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    ExecutionDebugger(Library *lib, ModuleCache *cache, LogEvents *events, std::ostream &os);
    ~ExecutionDebugger();
};

class MemoryDebugger : public LogEvents {
private:
    enum Type { UNDEFINED, LOOK_FOR_VALUE };

    std::ostream &m_os;

    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;

    Type m_analysisType;

    uint64_t m_valueToFind;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    void printHeader(const s2e::plugins::ExecutionTraceItemHeader &hdr);
    void doLookForValue(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                        const s2e::plugins::ExecutionTraceMemory &item);

    void doPageFault(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                     const s2e::plugins::ExecutionTracePageFault &item);

public:
    MemoryDebugger(Library *lib, ModuleCache *cache, LogEvents *events, std::ostream &os);
    ~MemoryDebugger();

    void lookForValue(uint64_t value) {
        m_analysisType = LOOK_FOR_VALUE;
        m_valueToFind = value;
    }
};

/**
 *  This is a collection of functions to analyze the execution traces
 *  for the purpose of debugging S2E.
 */
class Debugger {
private:
    std::string m_fileName;
    LogParser m_parser;

    ModuleCache *m_ModuleCache;
    Library m_binaries;

    void processCallItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr,
                         const s2e::plugins::ExecutionTraceCall &call);

public:
    Debugger(const std::string &file);
    ~Debugger();

    void process();
};
}

#endif
