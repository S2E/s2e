///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ExceptionTracer.h"
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <TraceEntries.pb.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExceptionTracer, "Traces CPU exception", "", "ExecutionTracer");

void ExceptionTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    s2e()->getCorePlugin()->onException.connect(sigc::mem_fun(*this, &ExceptionTracer::onException));
}

void ExceptionTracer::onException(S2EExecutionState *state, unsigned vec, uint64_t pc) {
    s2e_trace::PbTraceException item;
    item.set_pc(state->regs()->getPc());
    item.set_vector(vec);
    m_tracer->writeData(state, item, s2e_trace::TRACE_EXCEPTION);
}

} // namespace plugins
} // namespace s2e
