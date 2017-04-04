///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_FORKPROFILER_H
#define S2ETOOLS_FORKPROFILER_H

#include <ostream>

namespace s2etools {

class Library;

class ForkProfiler {
public:
    struct Fork {
        uint32_t id;
        uint64_t pid;
        uint64_t relPc, pc;
        std::string module;
        std::vector<uint32_t> children;
    };

    struct ForkPoint {
        uint64_t pc, pid;
        uint64_t count;
        uint64_t line;
        std::string file, function, module;
        uint64_t loadbase, imagebase;

        bool operator()(const ForkPoint &fp1, const ForkPoint &fp2) const {
            if (fp1.pid == fp2.pid) {
                return fp1.pc < fp2.pc;
            } else {
                return fp1.pid < fp2.pid;
            }
        }
    };

    struct ForkPointByCount {
        bool operator()(const ForkPoint &fp1, const ForkPoint &fp2) const {
            if (fp1.count == fp2.count) {
                if (fp1.pid == fp2.pid) {
                    return fp1.pc < fp2.pc;
                } else {
                    return fp1.pid < fp2.pid;
                }
            } else {
                return fp1.count < fp2.count;
            }
        }
    };

    typedef std::vector<Fork> ForkList;
    typedef std::set<ForkPoint, ForkPoint> ForkPoints;
    typedef std::set<ForkPoint, ForkPointByCount> ForkPointsByCount;

private:
    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;
    ForkList m_forks;
    ForkPoints m_forkPoints;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    void doProfile(const s2e::plugins::ExecutionTraceItemHeader &hdr, const s2e::plugins::ExecutionTraceFork *te);
    void doGraph(const s2e::plugins::ExecutionTraceItemHeader &hdr, const s2e::plugins::ExecutionTraceFork *te);

public:
    ForkProfiler(Library *lib, ModuleCache *cache, LogEvents *events);
    virtual ~ForkProfiler();

    void process();

    void outputProfile(const std::string &path) const;
    void outputGraph(const std::string &path) const;
};
}

#endif
