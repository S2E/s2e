///
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include "FunctionMonitor2.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionMonitor2, "Function monitoring plugin", "", "ExecutionTracer", "ProcessExecutionDetector",
                  "OSMonitor", "ModuleMap");

void FunctionMonitor2::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_map = s2e()->getPlugin<ModuleMap>();
    m_processDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &FunctionMonitor2::onTranslateBlockEnd));
}

void FunctionMonitor2::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc, bool isStatic, uint64_t staticTarget) {
    if (m_monitor->isKernelAddress(pc)) {
        return;
    }

    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor2::onFunctionCall));
    }
}

void FunctionMonitor2::onFunctionCall(S2EExecutionState *state, uint64_t callerPc) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    uint64_t calleePc = state->getPc();

    const ModuleDescriptor *callerMod = m_map->getModule(state, callerPc);
    const ModuleDescriptor *calleeMod = m_map->getModule(state, calleePc);

    if (callerMod) {
        callerPc = callerMod->ToNativeBase(callerPc);
    }

    if (calleeMod) {
        calleePc = calleeMod->ToNativeBase(calleePc);
    }

    onCall.emit(state, callerMod, calleeMod, callerPc, calleePc);
}

} // namespace plugins
} // namespace s2e
