///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TranslationBlockTracer, "Tracer for executed translation blocks", "TranslationBlockTracer",
                  "ExecutionTracer");

void TranslationBlockTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    // Retrict monitoring to configured modules only
    m_monitorModules = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModules");
    if (m_monitorModules && !m_detector) {
        getWarningsStream() << "TranslationBlockTracer: The monitorModules option requires ModuleExecutionDetector\n";
        exit(-1);
    }

    bool ok = false;
    // Specify whether or not to enable cutom instructions for enabling/disabling tracing
    bool manualTrigger = s2e()->getConfig()->getBool(getConfigKey() + ".manualTrigger", false, &ok);

    // Whether or not to flush the translation block cache when enabling/disabling tracing.
    // This can be useful when tracing is enabled in the middle of a run where most of the blocks
    // are already translated without the tracing instrumentation enabled.
    // The default behavior is ON, because otherwise it may produce confusing results.
    m_flushTbOnChange = s2e()->getConfig()->getBool(getConfigKey() + ".flushTbCache", true);

    if (manualTrigger) {
        s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onCustomInstruction));
    } else {
        enableTracing();
    }
}

bool TranslationBlockTracer::tracingEnabled() {
    return m_tbStartConnection.connected() || m_tbEndConnection.connected();
}

void TranslationBlockTracer::enableTracing() {
    if (m_tbStartConnection.connected()) {
        return;
    }

    if (g_s2e_state != NULL && m_flushTbOnChange) {
        se_tb_safe_flush();
    }

    if (m_monitorModules) {
        m_tbStartConnection = m_detector->onModuleTranslateBlockStart.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockStart));

        m_tbEndConnection = m_detector->onModuleTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockEnd));
    } else {
        m_tbStartConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockStart));

        m_tbEndConnection = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onTranslateBlockEnd));
    }
}

void TranslationBlockTracer::disableTracing() {
    if (m_flushTbOnChange) {
        se_tb_safe_flush();
    }

    m_tbStartConnection.disconnect();
    m_tbEndConnection.disconnect();
}

void TranslationBlockTracer::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockStart));
}

void TranslationBlockTracer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t endPc, bool staticTarget,
                                                 uint64_t targetPc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockEnd));
}

void TranslationBlockTracer::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                         const ModuleDescriptor &module, TranslationBlock *tb,
                                                         uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockStart));
}

void TranslationBlockTracer::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                       const ModuleDescriptor &module, TranslationBlock *tb,
                                                       uint64_t endPc, bool staticTarget, uint64_t targetPc) {
    signal->connect(sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockEnd));
}

template <typename T>
bool TranslationBlockTracer::getConcolicValue(S2EExecutionState *state, unsigned offset, T *value) {
    auto size = sizeof(T);

    klee::ref<klee::Expr> expr = state->regs()->read(offset, size * 8);
    if (isa<klee::ConstantExpr>(expr)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(expr);
        *value = ce->getZExtValue();
        return true;
    }

    if (ConcolicMode) {
        klee::ref<klee::ConstantExpr> ce;
        ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
        *value = ce->getZExtValue();
        return true;
    } else {
        return false;
    }
}

void TranslationBlockTracer::trace(S2EExecutionState *state, uint64_t pc, uint32_t type) {
    s2e_trace::PbTraceTranslationBlockFull tb;

    if (type == s2e_trace::PbTraceItemHeaderType::TRACE_TB_START) {
        if (state->getPointerSize() != 2) {
            if (pc != state->getTb()->pc) {
                getWarningsStream() << "BUG! pc=" << hexval(pc) << " tbpc=" << hexval(state->getTb()->pc) << '\n';
                exit(-1);
            }
        }
    }

    tb.set_pc(pc);
    tb.set_target_pc(state->regs()->getPc());
    tb.set_tb_type(s2e_trace::PbTraceTbType(state->getTb()->se_tb_type));
    tb.set_symb_mask(0);
    tb.set_size(state->getTb()->size);
    tb.set_running_concrete(state->isRunningConcrete());
    tb.set_running_exception_emulation_code(state->isRunningExceptionEmulationCode());

    uint32_t symbMask = 0;

    for (unsigned i = 0; i < sizeof(env->regs) / sizeof(env->regs[0]); ++i) {
        // XXX: make it portable across architectures
        unsigned offset = offsetof(CPUX86State, regs[i]);
        target_ulong concrete_data;
        if (!state->regs()->read(offset, &concrete_data, sizeof(concrete_data), false)) {
            if (ConcolicMode) {
                getConcolicValue(state, offset, &concrete_data);
            }

            symbMask |= 1 << i;
        }

        tb.add_registers(concrete_data);
    }

    tb.set_symb_mask(symbMask);
    m_tracer->writeData(state, tb, type);
}

void TranslationBlockTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, s2e_trace::PbTraceItemHeaderType::TRACE_TB_START);
}

void TranslationBlockTracer::onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, s2e_trace::PbTraceItemHeaderType::TRACE_TB_END);
}

// TODO: remove this (or switch to s2e_invoke_plugin)
void TranslationBlockTracer::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    // XXX: find a better way of allocating custom opcodes
    if (!OPCODE_CHECK(opcode, TB_TRACER_OPCODE)) {
        return;
    }

    // XXX: remove this mess. Should have a function for extracting
    // info from opcodes.
    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;

    TbTracerOpcodes opc = (TbTracerOpcodes) op;
    switch (opc) {
        case Enable:
            enableTracing();
            break;

        case Disable:
            disableTracing();
            break;

        default:
            getWarningsStream() << "unsupported opcode " << hexval(opc) << '\n';
            break;
    }
}

bool TranslationBlockTracer::getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
    return false;
}

bool TranslationBlockTracer::setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
    if (name == "trace") {
        if (value == "1") {
            enableTracing();
        } else {
            disableTracing();
        }
        return true;
    }
    return false;
}

} // namespace plugins
} // namespace s2e
