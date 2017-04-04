///
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include "FunctionMonitor2.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionMonitor2, "Function monitoring plugin", "", "ExecutionTracer", "ProcessExecutionDetector",
                  "OSMonitor", "ModuleMap");

void FunctionMonitor2::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_map = s2e()->getPlugin<ModuleMap>();
    m_processDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &FunctionMonitor2::onTranslateBlockEnd));
}

void FunctionMonitor2::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc, bool isStatic, uint64_t staticTarget) {
    enum ETranslationBlockType tb_type = tb->se_tb_type;
    if (!(tb_type == TB_CALL || tb_type == TB_CALL_IND)) {
        return;
    }

    if (m_monitor->isKernelAddress(pc)) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &FunctionMonitor2::onExecuteStart));
}

void FunctionMonitor2::onExecuteStart(S2EExecutionState *state, uint64_t pc) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    uint64_t ra = 0;
    state->getReturnAddress(&ra);

    const ModuleDescriptor *sm = m_map->getModule(state, pc);
    const ModuleDescriptor *dm = m_map->getModule(state, pc);

    if (sm) {
        ra = sm->ToNativeBase(ra);
    }

    if (dm) {
        pc = dm->ToNativeBase(pc);
    }

    onCall.emit(state, sm, dm, ra, pc);
}

} // namespace plugins
} // namespace s2e
