///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "TestCase.h"
#include <cassert>
#include <iomanip>
#include <iostream>

using namespace s2e::plugins;

namespace s2etools {

TestCase::TestCase(LogEvents *events) {
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &TestCase::onItem));
    m_events = events;
}

TestCase::~TestCase() {
    m_connection.disconnect();
}

void TestCase::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    if (hdr.type != s2e::plugins::TRACE_TESTCASE) {
        return;
    }

    TestCaseState *state = static_cast<TestCaseState *>(m_events->getState(this, &TestCaseState::factory));

    std::cerr << "TestCase stateId=" << hdr.stateId << std::endl;
    if (state->m_foundInputs) {
        std::cerr << "The execution trace has multiple input sets. Make sure you used the PathBuilder filter."
                  << std::endl;
        assert(false);
    }
    ExecutionTraceTestCase::deserialize(item, hdr.size, state->m_inputs);
    state->m_foundInputs = true;
}

void TestCaseState::printInputsLine(std::ostream &os) {
    if (!m_foundInputs) {
        os << "No concrete inputs found in the trace. Make sure you used the TestCaseGenerator plugin.";
        return;
    }

    ExecutionTraceTestCase::ConcreteInputs::iterator it;

    for (it = m_inputs.begin(); it != m_inputs.end(); ++it) {
        const ExecutionTraceTestCase::VarValuePair &vp = *it;
        // os << vp.first << ": ";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            os << std::hex << std::setw(2) << std::right << std::setfill('0') << (unsigned) vp.second[i] << ' ';
        }
    }
}

void TestCaseState::printInputs(std::ostream &os) {
    if (!m_foundInputs) {
        os << "No concrete inputs found in the trace. Make sure you used the TestCaseGenerator plugin." << std::endl;
        return;
    }

    ExecutionTraceTestCase::ConcreteInputs::iterator it;
    os << "Concrete inputs:" << std::endl;

    for (it = m_inputs.begin(); it != m_inputs.end(); ++it) {
        const ExecutionTraceTestCase::VarValuePair &vp = *it;
        os << "  " << vp.first << ": ";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            os << std::setw(2) << std::right << std::setfill('0') << (unsigned) vp.second[i] << ' ';
        }

        os << std::setfill(' ') << std::endl;
    }
}

ItemProcessorState *TestCaseState::factory() {
    return new TestCaseState();
}

TestCaseState::TestCaseState() {
    m_foundInputs = false;
}

TestCaseState::~TestCaseState() {
}

ItemProcessorState *TestCaseState::clone() const {
    return new TestCaseState(*this);
}
}
