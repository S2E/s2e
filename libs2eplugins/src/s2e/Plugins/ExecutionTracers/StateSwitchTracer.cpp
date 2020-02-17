///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <s2e/S2E.h>

#include <TraceEntries.pb.h>

#include "StateSwitchTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StateSwitchTracer, "Traces state switches", "", "ExecutionTracer");

void StateSwitchTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &StateSwitchTracer::onStateSwitch));
}

void StateSwitchTracer::onStateSwitch(S2EExecutionState *currentState, S2EExecutionState *nextState) {
    s2e_trace::PbTraceStateSwitch item;
    item.set_new_state(nextState->getID());
    m_tracer->writeData(currentState, item, s2e_trace::TRACE_STATE_SWITCH);
}

} // namespace plugins
} // namespace s2e
