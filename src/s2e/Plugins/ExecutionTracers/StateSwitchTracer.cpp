///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>

#include "StateSwitchTracer.h"
#include "TraceEntries.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StateSwitchTracer, "Traces state switches", "", "ExecutionTracer");

void StateSwitchTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &StateSwitchTracer::onStateSwitch));
}

void StateSwitchTracer::onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState) {
    ExecutionTraceStateSwitch e;
    e.newStateId = nextState->getID();

    m_tracer->writeData(currentState, &e, sizeof(e), TRACE_STATE_SWITCH);
}

} // namespace plugins
} // namespace s2e
