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

bool TranslationBlockTracer::getConcolicValue(S2EExecutionState *state, unsigned offset, uint64_t *value,
                                              unsigned size) {
    klee::ref<klee::Expr> expr = state->regs()->readSymbolicRegion(offset, size * 8);
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
        *value = 0xdeadbeef;
        return false;
    }
}

// The real tracing is done here
//-----------------------------
void TranslationBlockTracer::trace(S2EExecutionState *state, uint64_t pc, ExecTraceEntryType type) {
    // XXX: dirty hack
    // tb and tb64 must overlap.
    // We use tb for 32-bits morde and tb64 for 64-bits.
    union {
        ExecutionTraceTb tb;
        ExecutionTraceTb64 tb64;
    };

    if (type == TRACE_TB_START) {
        if (state->getPointerSize() != 2) {
            if (pc != state->getTb()->pc) {
                getWarningsStream() << "BUG! pc=" << hexval(pc) << " tbpc=" << hexval(state->getTb()->pc) << '\n';
                exit(-1);
            }
        }
    }

    tb.pc = pc;
    tb.targetPc = state->getPc();
    tb.tbType = state->getTb()->se_tb_type;
    tb.symbMask = 0;
    tb.size = state->getTb()->size;
    tb.flags = 0;
    if (state->isRunningConcrete()) {
        tb.flags |= ExecutionTraceTb::RUNNING_CONCRETE;
    }
    if (state->isRunningExceptionEmulationCode()) {
        tb.flags |= ExecutionTraceTb::RUNNING_EXCEPTION_EMULATION_CODE;
    }
    memset(tb.registers, 0x55, sizeof(tb.registers));

#ifdef ENABLE_TRACE_STACK
    memset(tb.stackByteMask, 0, sizeof(tb.stackByteMask));
    memset(tb.stackSymbMask, 0, sizeof(tb.stackSymbMask));
    memset(tb.stack, 0x55, sizeof(tb.stack));
#endif

    /* Handle the first 8 gp registers */
    assert(sizeof(tb.symbMask) * 8 >= sizeof(tb.registers) / sizeof(tb.registers[0]));
    for (unsigned i = 0; i < sizeof(tb.registers) / sizeof(tb.registers[0]); ++i) {
        // XXX: make it portable across architectures
        unsigned size = sizeof(target_ulong) < sizeof(*tb.registers) ? sizeof(target_ulong) : sizeof(*tb.registers);
        unsigned offset = offsetof(CPUX86State, regs[i]);
        if (!state->readCpuRegisterConcrete(offset, &tb.registers[i], size)) {
            tb.registers[i] = 0xDEADBEEF;

            if (ConcolicMode) {
                getConcolicValue(state, offset, &tb.registers[i], size);
            }

            tb.symbMask |= 1 << i;
        }
    }

#ifdef ENABLE_TRACE_STACK
    assert(TRACE_STACK_SIZE % CHAR_BIT == 0);
    assert(sizeof(tb.stackByteMask) * CHAR_BIT >= ARRAY_SIZE(tb.stack));
    assert(sizeof(tb.stackSymbMask) * CHAR_BIT >= ARRAY_SIZE(tb.stack));
    for (unsigned i = 0; i < ARRAY_SIZE(tb.stack); i++) {
        klee::ref<klee::Expr> val = state->readMemory8(tb.registers[R_ESP] + i);
        if (val.isNull()) {
            continue;
        }

        BITMASK_SET(tb.stackByteMask, i);

        if (isa<klee::ConstantExpr>(val)) {
            tb.stack[i] = dyn_cast<klee::ConstantExpr>(val)->getZExtValue();
        } else {
            BITMASK_SET(tb.stackSymbMask, i);

            if (ConcolicMode) {
                klee::ref<klee::ConstantExpr> ce;
                ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(val));
                tb.stack[i] = ce->getZExtValue();
            }
        }
    }
#endif

#ifdef TARGET_X86_64
    if (state->getPointerSize() == 8) {
        /* Handle the 8 other regs */
        tb64.symbMask = 0;
        for (unsigned i = 0; i < sizeof(tb64.extendedRegisters) / sizeof(tb64.extendedRegisters[0]); ++i) {
            // XXX: make it portable across architectures
            unsigned size = sizeof(target_ulong) < sizeof(*tb.registers) ? sizeof(target_ulong) : sizeof(*tb.registers);
            unsigned offset = offsetof(CPUX86State, regs[CPU_NB_REGS32 + i]);
            if (!state->readCpuRegisterConcrete(offset, &tb64.extendedRegisters[i], size)) {
                tb64.extendedRegisters[i] = 0xDEADBEEF;
                tb64.symbMask |= 1 << i;

                if (ConcolicMode) {
                    getConcolicValue(state, offset, &tb64.extendedRegisters[i], size);
                }
            }
        }

        if (type == TRACE_TB_START) {
            type = TRACE_TB_START_X64;
        } else if (type == TRACE_TB_END) {
            type = TRACE_TB_END_X64;
        }

        m_tracer->writeData(state, &tb64, sizeof(tb64), type);
    } else {
        m_tracer->writeData(state, &tb, sizeof(tb), type);
    }

#else
    m_tracer->writeData(state, &tb, sizeof(tb), type);
#endif
}

void TranslationBlockTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, TRACE_TB_START);
}

void TranslationBlockTracer::onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc) {
    trace(state, pc, TRACE_TB_END);
}

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
            getWarningsStream() << "MemoryTracer: unsupported opcode " << hexval(opc) << '\n';
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
