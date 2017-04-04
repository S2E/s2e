///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_TESTCASE_H
#define S2ETOOLS_EXECTRACER_TESTCASE_H

#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include "LogParser.h"

namespace s2etools {

class TestCase {
private:
    sigc::connection m_connection;
    LogEvents *m_events;

    void onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item);

public:
    TestCase(LogEvents *events);
    ~TestCase();
};

class TestCaseState : public ItemProcessorState {
private:
    s2e::plugins::ExecutionTraceTestCase::ConcreteInputs m_inputs;
    bool m_foundInputs;

public:
    TestCaseState();
    virtual ~TestCaseState();

    static ItemProcessorState *factory();
    virtual ItemProcessorState *clone() const;

    bool getInputs(const s2e::plugins::ExecutionTraceTestCase::ConcreteInputs &out) const;
    bool hasInputs() const {
        return m_foundInputs;
    }
    void printInputs(std::ostream &os);
    void printInputsLine(std::ostream &os);

    friend class TestCase;
};
}
#endif
