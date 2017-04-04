///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_PFPROFILER_H
#define S2ETOOLS_PFPROFILER_H

#include "lib/BinaryReaders/Library.h"
#include "lib/ExecutionTracer/LogParser.h"

#include <ostream>

namespace s2etools {

class ModuleCache;

class PfProfiler {
private:
    std::string m_FileName;
    s2etools::LogParser m_Parser;

    Library m_binaries;

    s2etools::ModuleCache *m_ModuleCache;

public:
    PfProfiler(const std::string &file);
    ~PfProfiler();

    void process();
    void extractAggregatedData();
};
}

#endif
