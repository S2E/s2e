///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_PLUGINS_TBTRACER_H
#define S2E_PLUGINS_TBTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include "ExecutionTracer.h"
#include "ModuleTracing.h"

namespace s2e {
namespace plugins {

class TranslationBlockTracer : public Plugin {
    S2E_PLUGIN
public:
    enum TraceType { TB_START = 0, TB_END = 1, MAX_ITEMS = 2 };

    TranslationBlockTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize(void);

    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

private:
    ExecutionTracer *m_tracer;
    ProcessExecutionDetector *m_detector;

    bool m_traceTbStart;
    bool m_traceTbEnd;

    ModuleTracing m_modules;

    bool isModuleTraced(S2EExecutionState *state, uint64_t pc);

    void onInitializationComplete(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);

    void onBlockStartEnd(S2EExecutionState *state, uint64_t pc, bool isStart);
    void onBlockStart(S2EExecutionState *state, uint64_t pc);
    void onBlockEnd(S2EExecutionState *state, uint64_t pc);

public:
    void enableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type);
    void disableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type);
    bool tracingEnabled(S2EExecutionState *state, TranslationBlockTracer::TraceType type);

    void trace(S2EExecutionState *state, uint64_t pc, uint32_t type /* s2e_trace::PbTraceItemHeaderType */);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_TBTRACER_H
