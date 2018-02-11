///
/// Copyright (C) 2011 - 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cpu/tb.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <list>
#include <unordered_map>

#include "LibraryCallMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LibraryCallMonitor, "Monitors external library function calls", "", "ModuleMap", "OSMonitor",
                  "ProcessExecutionDetector", "Vmi");

void LibraryCallMonitor::initialize() {
    m_map = s2e()->getPlugin<ModuleMap>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_vmi = s2e()->getPlugin<Vmi>();

    ConfigFile *cfg = s2e()->getConfig();
    m_monitorAllModules = cfg->getBool(getConfigKey() + ".monitorAllModules");
    m_monitorIndirectJumps = cfg->getBool(getConfigKey() + ".monitorIndirectJumps");

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onTranslateBlockEnd));
}

void LibraryCallMonitor::logLibraryCall(S2EExecutionState *state, const std::string &callerMod, uint64_t pc,
                                        unsigned sourceType, const std::string &calleeMod,
                                        const std::string &function) const {
    std::string sourceTypeDesc = (sourceType == TB_CALL_IND) ? " called " : " jumped to ";

    getInfoStream(state) << callerMod << "@" << hexval(pc) << sourceTypeDesc << calleeMod << "." << function << "\n";
}

void LibraryCallMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, bool isStatic, uint64_t staticTarget) {
    // Library calls/jumps are always indirect
    if (tb->se_tb_type == TB_CALL_IND || (m_monitorIndirectJumps && tb->se_tb_type == TB_JMP_IND)) {
        signal->connect(
            sigc::bind(sigc::mem_fun(*this, &LibraryCallMonitor::onIndirectCallOrJump), (unsigned) tb->se_tb_type));
    }
}

void LibraryCallMonitor::onIndirectCallOrJump(S2EExecutionState *state, uint64_t pc, unsigned sourceType) {
    // Only interested in the processes specified in the ProcessExecutionDetector config
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    // Only interested in particular modules loaded in the process
    const ModuleDescriptor *currentMod = m_map->getModule(state, pc);
    if (!(m_monitorAllModules || (currentMod && m_procDetector->isTracked(state)))) {
        return;
    }

    // Get the loaded modules for the executing process
    uint64_t pid = m_monitor->getPid(state);
    ModuleDescriptorList mods = m_map->getModulesByPid(state, pid);

    uint64_t targetAddr = state->getPc();

    // Find the module that contains the call target
    //
    // First check the ModuleMap cache. If it is not in the cache, search all the loaded modules until the one that
    // exports the call target is found
    const ModuleMap::Export *cachedExp = m_map->getExport(state, targetAddr);

    if (cachedExp) {
        logLibraryCall(state, currentMod->Name, pc, sourceType, cachedExp->first->Name, cachedExp->second);
        onLibraryCall.emit(state, *(cachedExp->first), targetAddr);
    } else {
        for (auto const &mod : mods) {
            if (mod->Contains(targetAddr)) {
                vmi::Exports exps;
                if (!m_vmi->getExports(state, *mod, exps)) {
                    getWarningsStream(state) << "unable to get exports for " << mod->Name << "\n";
                    break;
                }

                // Find the export that matches the call target
                for (auto const &exp : exps) {
                    if (targetAddr == exp.second) {
                        logLibraryCall(state, currentMod->Name, pc, sourceType, mod->Name, exp.first);
                        onLibraryCall.emit(state, *mod, targetAddr);

                        // Cache the result
                        m_map->cacheExport(state, targetAddr, {mod, exp.first});

                        break;
                    }
                }

                break;
            }
        }
    }
}

} // namespace plugins
} // namespace s2e
