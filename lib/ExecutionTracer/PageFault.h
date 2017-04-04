///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_PageFault_H
#define S2ETOOLS_EXECTRACER_PageFault_H

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include "LogParser.h"

namespace s2etools {

class ModuleCache;

class PageFault {
private:
    sigc::connection m_connection;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

    ModuleCache *m_mc;
    LogEvents *m_events;

    bool m_trackModule;
    std::string m_module;

public:
    PageFault(LogEvents *events, ModuleCache *mc);
    ~PageFault();

    void setModule(const std::string &s) {
        m_module = s;
        m_trackModule = true;
    }
};

class PageFaultState : public ItemProcessorState {
private:
    uint64_t m_totalPageFaults;
    uint64_t m_totalTlbMisses;

public:
    static ItemProcessorState *factory();
    PageFaultState();
    virtual ~PageFaultState();
    virtual ItemProcessorState *clone() const;
    friend class PageFault;

    uint64_t getPageFaults() const {
        return m_totalPageFaults;
    }

    uint64_t getTlbMisses() const {
        return m_totalTlbMisses;
    }
};
}
#endif
