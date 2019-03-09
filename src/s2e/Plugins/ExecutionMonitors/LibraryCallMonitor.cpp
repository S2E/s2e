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

namespace {

class LibraryCallMonitorState : public PluginState {
    typedef std::unordered_map<uint64_t, std::string> ExportMap;
    std::unordered_map<uint64_t, ExportMap> m_map;

public:
    LibraryCallMonitorState() {
    }

    virtual ~LibraryCallMonitorState() {
    }

    virtual LibraryCallMonitorState *clone() const {
        return new LibraryCallMonitorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LibraryCallMonitorState();
    }

    bool get(uint64_t pid, uint64_t address, std::string &exportName) const {
        auto it = m_map.find(pid);
        if (it == m_map.end()) {
            return false;
        }

        auto it2 = (*it).second.find(address);
        if (it2 == (*it).second.end()) {
            return false;
        }

        exportName = (*it2).second;
        return true;
    }

    void add(uint64_t pid, uint64_t address, const std::string &exportName) {
        m_map[pid][address] = exportName;
    }

    void remove(uint64_t pid) {
        m_map.erase(pid);
    }

    void remove(const ModuleDescriptor &mod) {
        auto it = m_map.find(mod.Pid);
        if (it == m_map.end()) {
            return;
        }

        std::vector<uint64_t> toDelete;
        auto exports = (*it).second;
        for (auto eit : exports) {
            if (mod.Contains(eit.first)) {
                toDelete.push_back(eit.first);
            }
        }

        for (auto it2 : toDelete) {
            exports.erase(it2);
        }
    }
};
}

void LibraryCallMonitor::initialize() {
    m_map = s2e()->getPlugin<ModuleMap>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_vmi = s2e()->getPlugin<Vmi>();

    ConfigFile *cfg = s2e()->getConfig();
    m_monitorAllModules = cfg->getBool(getConfigKey() + ".monitorAllModules");
    m_monitorIndirectJumps = cfg->getBool(getConfigKey() + ".monitorIndirectJumps");

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onTranslateBlockEnd));

    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onProcessUnload));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onModuleUnload));
}

void LibraryCallMonitor::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid,
                                         uint64_t returnCode) {
    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);
    plgState->remove(pid);
}

void LibraryCallMonitor::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);
    plgState->remove(module);
}

void LibraryCallMonitor::logLibraryCall(S2EExecutionState *state, const std::string &callerMod, uint64_t pc,
                                        unsigned sourceType, const std::string &calleeMod, const std::string &function,
                                        uint64_t pid) const {
    std::string sourceTypeDesc = (sourceType == TB_CALL_IND) ? " called " : " jumped to ";

    getInfoStream(state) << callerMod << "@" << hexval(pc) << sourceTypeDesc << calleeMod << "!" << function
                         << " (pid=" << hexval(pid) << ")\n";
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
    auto currentMod = m_map->getModule(state, pc);
    if (!(m_monitorAllModules || (currentMod && m_procDetector->isTracked(state)))) {
        return;
    }

    auto current_mod = m_map->getModule(state, pc);

    auto mod = m_map->getModule(state);
    if (!mod) {
        return;
    }

    if (mod == current_mod) {
        // Indirect calls within the same module don't count as library calls
        return;
    }

    uint64_t targetAddr = state->regs()->getPc();

    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);

    std::string exportName;
    if (!plgState->get(mod->Pid, targetAddr, exportName)) {
        vmi::Exports exps;
        auto exe = m_vmi->getFromDisk(*mod, true);
        if (!exe) {
            return;
        }

        auto pe = std::dynamic_pointer_cast<vmi::PEFile>(exe);
        if (!pe) {
            getWarningsStream(state) << "we only support PE files for now\n";
            return;
        }

        auto exports = pe->getExports();
        auto it = exports.find(targetAddr - mod->LoadBase);
        if (it != exports.end()) {
            plgState->add(mod->Pid, targetAddr, (*it).second);
            exportName = (*it).second;
        } else {
            // Did not find any export
            getWarningsStream(state) << "Could not get export name for address " << hexval(targetAddr) << "\n";
            // Entry with an empty name is a blacklist, so we don't incur lookup costs all the time
            plgState->add(mod->Pid, targetAddr, "");
            return;
        }
    }

    if (exportName.size() == 0) {
        return;
    }

    logLibraryCall(state, mod->Name, pc, sourceType, mod->Name, exportName, mod->Pid);
    onLibraryCall.emit(state, *mod, targetAddr);
}

} // namespace plugins
} // namespace s2e
