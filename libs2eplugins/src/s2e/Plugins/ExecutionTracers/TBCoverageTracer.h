/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Cisco Systems
 * Copyright (C) 2016-2019, Cyberhaven
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

#ifndef S2E__BLOCK_COVERAGE_TRACER_H
#define S2E__BLOCK_COVERAGE_TRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

class TBCoverageTracer : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
public:
    TBCoverageTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize(void);

    typedef enum { Enable = 0, Disable = 1 } TraceOpcode;

private:
    ExecutionTracer *m_tracer;
    ModuleExecutionDetector *m_detector;

    bool m_flushTbOnChange;
    bool m_manualTrigger;

    sigc::connection m_tbCompleteConnection;

    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t endPc);

    void trace(S2EExecutionState *state, uint64_t startPc, uint64_t endPc, TranslationBlock *tb);

    void enableTracing();
    void disableTracing();

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_BLOCK_COVERAGE_H
