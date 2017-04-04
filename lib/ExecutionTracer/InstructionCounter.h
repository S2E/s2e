///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_ICOUNT_H
#define S2ETOOLS_EXECTRACER_ICOUNT_H

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include "LogParser.h"

namespace s2etools {

class InstructionCounter {
private:
    sigc::connection m_connection;
    LogEvents *m_events;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    InstructionCounter(LogEvents *events);

    ~InstructionCounter();
};

class InstructionCounterState : public ItemProcessorState {
private:
    uint64_t m_icount;

public:
    InstructionCounterState();
    virtual ~InstructionCounterState();

    static ItemProcessorState *factory();
    virtual ItemProcessorState *clone() const;

    void printCounter(std::ostream &os);
    uint64_t getCount() const {
        return m_icount;
    }

    friend class InstructionCounter;
};
}
#endif
