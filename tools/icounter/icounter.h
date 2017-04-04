///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_PFPROFILER_H
#define S2ETOOLS_PFPROFILER_H

#include "lib/ExecutionTracer/LogParser.h"
#include "lib/ExecutionTracer/ModuleParser.h"

#include <ostream>

#include "lib/BinaryReaders/Library.h"

namespace s2etools {

class InstructionCounterTool {
public:
private:
    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    void doProfile(const s2e::plugins::ExecutionTraceItemHeader &hdr, const s2e::plugins::ExecutionTraceFork *te);
    void doGraph(const s2e::plugins::ExecutionTraceItemHeader &hdr, const s2e::plugins::ExecutionTraceFork *te);

public:
    InstructionCounterTool(Library *lib, ModuleCache *cache, LogEvents *events);
    virtual ~InstructionCounterTool();

    void process();

    void outputProfile(const std::string &path) const;
    void outputGraph(const std::string &path) const;
};
}
}

#endif
