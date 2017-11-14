///
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Cisco Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Cisco Systems nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CISCO SYSTEMS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include "TBCoverageTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TBCoverageTracer, "Tracer for translation blocks", "TBCoverageTracer", "ExecutionTracer",
                  "ModuleExecutionDetector");

void TBCoverageTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    m_manualTrigger = s2e()->getConfig()->getBool(getConfigKey() + ".manualTrigger", false, NULL);

    // Whether or not to flush the translation block cache when
    // enabling/disabling tracing.
    // This can be useful when tracing is enabled in the middle of a run
    // where most of the blocks are already translated without the tracing
    // instrumentation enabled.
    // The default behavior is ON, because otherwise it may produce
    // confusing results.
    m_flushTbOnChange = s2e()->getConfig()->getBool(getConfigKey() + ".flushTbCache", true);

    if (!m_manualTrigger) {
        enableTracing();
    }
}

void TBCoverageTracer::enableTracing() {
    getWarningsStream() << "TBCoverageTracer: enabling tracing " << '\n';

    m_tbCompleteConnection = m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &TBCoverageTracer::onModuleTranslateBlockComplete));
}

void TBCoverageTracer::disableTracing() {
    getWarningsStream() << "TBCoverageTracer: disabling tracing " << '\n';

    m_tbCompleteConnection.disconnect();
}

void TBCoverageTracer::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                      TranslationBlock *tb, uint64_t endPc) {
    trace(state, tb->pc, endPc, TRACE_BLOCK, tb);
}

void TBCoverageTracer::trace(S2EExecutionState *state, uint64_t startPc, uint64_t endPc, ExecTraceEntryType type,
                             TranslationBlock *tb) {
    ExecutionTraceBlock traceItem;

    assert(type == TRACE_BLOCK);

    traceItem.startPc = startPc;
    traceItem.endPc = endPc;
    traceItem.tbType = tb->se_tb_type;

    m_tracer->writeData(state, &traceItem, sizeof(traceItem), type);
}

void TBCoverageTracer::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    if (!m_manualTrigger) {
        getWarningsStream(state) << "TBCoverageTracer : ignoring command, manualTrigger disabled\n";
        return;
    }

    TraceOpcode code;
    if (guestDataSize != sizeof(code)) {
        getWarningsStream(state) << "TBCoverageTracer: mismatched TraceOpcode size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &code, guestDataSize)) {
        getWarningsStream(state) << "TBCoverageTracer: could not read transmitted data\n";
        return;
    }

    switch (code) {
        case Enable: {
            enableTracing();
        } break;

        case Disable: {
            disableTracing();
        } break;

        default: {
            getInfoStream(state) << "TBCoverageTracer: "
                                 << "Invalid command " << hexval(code) << "\n";
            return;
        }
    }

    if (m_flushTbOnChange) {
        tb_flush(env);
        state->setPc(state->getPc() + 10);
        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
