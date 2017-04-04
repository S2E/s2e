///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_MODULEPARSER_H
#define S2ETOOLS_EXECTRACER_MODULEPARSER_H

#include <cassert>
#include <inttypes.h>
#include <map>
#include <ostream>
#include <set>
#include <string>

#include "LogParser.h"

namespace s2etools {

struct ModuleInstance {
    uint64_t Pid;
    uint64_t LoadBase;
    uint64_t ImageBase;
    uint64_t Size; // Used only for lookup
    std::string Name;

    ModuleInstance(const std::string &name, uint64_t pid, uint64_t loadBase, uint64_t size, uint64_t imageBase);

    bool operator<(const ModuleInstance &s) const {
        if (Pid == s.Pid) {
            return LoadBase + Size <= s.LoadBase;
        }
        return Pid < s.Pid;
    }

    void print(std::ostream &os) const;
};

struct ModuleInstanceCmp {
    bool operator()(const ModuleInstance *s1, const ModuleInstance *s2) const {
        if (s1->Pid == s2->Pid) {
            return s1->LoadBase + s1->Size <= s2->LoadBase;
        }
        return s1->Pid < s2->Pid;
    }
};

typedef std::set<ModuleInstance *, ModuleInstanceCmp> ModuleInstanceSet;

// Represents all the loaded modules at a given time
class ModuleCache {
private:
    LogEvents *m_events;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    ModuleCache(LogEvents *Events);
};

class ModuleCacheState : public ItemProcessorState {
private:
    ModuleInstanceSet m_Instances;

public:
    static ItemProcessorState *factory();
    ModuleCacheState();
    virtual ~ModuleCacheState();
    virtual ItemProcessorState *clone() const;

    bool loadModule(const std::string &name, uint64_t pid, uint64_t loadBase, uint64_t imageBase, uint64_t size);
    bool unloadModule(uint64_t pid, uint64_t loadBase);

    const ModuleInstance *getInstance(uint64_t pid, uint64_t pc) const;

    friend class ModuleCache;
};

struct InstructionDescriptor {
    const ModuleInstance *m;
    uint64_t loadBase; // xxx: fixme
    uint64_t pid, pc;

    bool operator<(const InstructionDescriptor &s) const {
        if (pid == s.pid) {
            return pc < s.pc;
        }
        return pid < s.pid;
    }
};
}

#endif
