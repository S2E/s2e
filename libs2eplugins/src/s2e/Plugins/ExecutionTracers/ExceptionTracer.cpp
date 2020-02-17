///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
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
