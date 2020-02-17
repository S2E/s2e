///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2019, Cyberhaven
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

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <iostream>

#include <TraceEntries.pb.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "TranslationBlockTracer.h"

#include <llvm/Support/CommandLine.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TranslationBlockTracer, "Tracer for executed translation blocks", "TranslationBlockTracer",
                  "ExecutionTracer", "ProcessExecutionDetector", "ModuleMap");

namespace {

class TranslationBlockTracerState : public PluginState {
private:
    bool m_enabledTrace[TranslationBlockTracer::MAX_ITEMS];

public:
    virtual TranslationBlockTracerState *clone() const {
        return new TranslationBlockTracerState(*this);
    }

    TranslationBlockTracerState() {
        m_enabledTrace[TranslationBlockTracer::TB_START] = false;
        m_enabledTrace[TranslationBlockTracer::TB_END] = false;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new TranslationBlockTracerState();
    }

    virtual ~TranslationBlockTracerState() {
    }

    inline void enable(TranslationBlockTracer::TraceType type, bool v) {
        m_enabledTrace[type] = v;
    }

    inline bool enabled(TranslationBlockTracer::TraceType type) const {
        return m_enabledTrace[type];
    }
};
} // namespace

void TranslationBlockTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_modules.initialize(s2e(), getConfigKey());

    m_traceTbStart = s2e()->getConfig()->getBool(getConfigKey() + ".traceTbStart");
    m_traceTbEnd = s2e()->getConfig()->getBool(getConfigKey() + ".traceTbEnd");

    s2e()->getCorePlugin()->onInitializationComplete.connect(
        sigc::mem_fun(*this, &TranslationBlockTracer::onInitializationComplete));
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockStart));
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockEnd));
}

void TranslationBlockTracer::onInitializationComplete(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(TranslationBlockTracerState, state);
    plgState->enable(TranslationBlockTracer::TB_START, m_traceTbStart);
    plgState->enable(TranslationBlockTracer::TB_END, m_traceTbEnd);
}

void TranslationBlockTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    auto tracedModule = m_modules.isModuleTraced(state, pc);
    if (tracedModule) {
        signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onBlockStart));
    }
}

void TranslationBlockTracer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    auto tracedModule = m_modules.isModuleTraced(state, pc);
    if (tracedModule) {
        signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onBlockEnd));
    }
}

void TranslationBlockTracer::onBlockStart(S2EExecutionState *state, uint64_t pc) {
    onBlockStartEnd(state, pc, true);
}

void TranslationBlockTracer::onBlockEnd(S2EExecutionState *state, uint64_t pc) {
    onBlockStartEnd(state, pc, false);
}

void TranslationBlockTracer::onBlockStartEnd(S2EExecutionState *state, uint64_t pc, bool isStart) {
    DECLARE_PLUGINSTATE(TranslationBlockTracerState, state);

    auto type = isStart ? TranslationBlockTracer::TB_START : TranslationBlockTracer::TB_END;
    if (!plgState->enabled(type)) {
        return;
    }

    if (!m_detector->isTracked(state)) {
        return;
    }

    if (isStart) {
        trace(state, pc, s2e_trace::PbTraceItemHeaderType::TRACE_TB_START);
    } else {
        trace(state, pc, s2e_trace::PbTraceItemHeaderType::TRACE_TB_END);
    }
}

bool TranslationBlockTracer::tracingEnabled(S2EExecutionState *state, TranslationBlockTracer::TraceType type) {
    DECLARE_PLUGINSTATE(TranslationBlockTracerState, state);
    return plgState->enabled(type);
}

void TranslationBlockTracer::enableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type) {
    DECLARE_PLUGINSTATE(TranslationBlockTracerState, state);
    return plgState->enable(type, true);
}

void TranslationBlockTracer::disableTracing(S2EExecutionState *state, TranslationBlockTracer::TraceType type) {
    DECLARE_PLUGINSTATE(TranslationBlockTracerState, state);
    return plgState->enable(type, false);
}

template <typename T> static bool getConcolicValue(S2EExecutionState *state, unsigned offset, T *value) {
    auto size = sizeof(T);

    klee::ref<klee::Expr> expr = state->regs()->read(offset, size * 8);
    if (isa<klee::ConstantExpr>(expr)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(expr);
        *value = ce->getZExtValue();
        return true;
    }

    klee::ref<klee::ConstantExpr> ce;
    ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
    *value = ce->getZExtValue();
    return true;
}

static s2e_trace::PbTraceRegisterData getRegs(S2EExecutionState *state) {
    s2e_trace::PbTraceRegisterData data;

    uint32_t symbMask = 0;

    for (unsigned i = 0; i < sizeof(env->regs) / sizeof(env->regs[0]); ++i) {
        // XXX: make it portable across architectures
        unsigned offset = offsetof(CPUX86State, regs[i]);
        target_ulong concreteData;

        if (!state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
            getConcolicValue(state, offset, &concreteData);
            symbMask |= 1 << i;
        }

        data.add_values(concreteData);
    }

    data.set_symb_mask(symbMask);

    return data;
}

static s2e_trace::PbTraceTbData getTbData(TranslationBlock *tb) {
    s2e_trace::PbTraceTbData data;

    data.set_tb_type(s2e_trace::PbTraceTbType(tb->se_tb_type));
    data.set_size(tb->size);
    data.set_first_pc(tb->pc);
    data.set_last_pc(tb->pcOfLastInstr);

    return data;
}

void TranslationBlockTracer::trace(S2EExecutionState *state, uint64_t pc, uint32_t type) {
    auto regs = getRegs(state);
    auto data = getTbData(state->getTb());

    if (type == s2e_trace::PbTraceItemHeaderType::TRACE_TB_START) {
        if (state->getPointerSize() != 2) {
            if (pc != state->getTb()->pc) {
                getWarningsStream() << "BUG! pc=" << hexval(pc) << " tbpc=" << hexval(state->getTb()->pc) << '\n';
                exit(-1);
            }
        }

        s2e_trace::PbTraceTranslationBlockStart tb;
        tb.set_allocated_data(&data);
        tb.set_allocated_regs(&regs);
        m_tracer->writeData(state, tb, type);
        tb.release_data();
        tb.release_regs();
    } else if (type == s2e_trace::PbTraceItemHeaderType::TRACE_TB_END) {
        s2e_trace::PbTraceTranslationBlockEnd tb;
        tb.set_allocated_data(&data);
        tb.set_allocated_regs(&regs);
        m_tracer->writeData(state, tb, type);
        tb.release_data();
        tb.release_regs();
    }
}

bool TranslationBlockTracer::getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
    return false;
}

bool TranslationBlockTracer::setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
    if (name == "trace") {
        if (value == "1") {
            enableTracing(state, TB_START);
            enableTracing(state, TB_END);
        } else {
            disableTracing(state, TB_START);
            disableTracing(state, TB_END);
        }
        return true;
    }
    return false;
}

} // namespace plugins
} // namespace s2e
