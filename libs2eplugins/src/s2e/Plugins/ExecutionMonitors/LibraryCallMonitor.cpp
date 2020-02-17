///
/// Copyright (C) 2011 - 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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
} // namespace

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

void LibraryCallMonitor::logLibraryCall(S2EExecutionState *state, const ModuleDescriptor &sourceMod,
                                        const ModuleDescriptor &destMod, uint64_t sourcePcAbsolute,
                                        uint64_t destPcAbsolute, unsigned sourceType,
                                        const std::string &function) const {
    std::string sourceTypeDesc = (sourceType == TB_CALL_IND) ? " called " : " jumped to ";

    uint64_t relSourcePc;
    uint64_t relDestPc;

    bool ok = true;
    ok &= sourceMod.ToNativeBase(sourcePcAbsolute, relSourcePc);
    ok &= destMod.ToNativeBase(destPcAbsolute, relDestPc);

    if (!ok) {
        getWarningsStream(state) << "could not get source/dest addresses for library call for modules "
                                 << sourceMod.Name << " -> " << destMod.Name << "\n";
        return;
    }

    getInfoStream(state) << sourceMod.Name << ":" << hexval(relSourcePc) << " (" << hexval(sourcePcAbsolute) << ") "
                         << sourceTypeDesc << destMod.Name << "!" << function << ":" << hexval(relDestPc) << " ("
                         << hexval(destPcAbsolute) << ")"
                         << " (pid=" << hexval(sourceMod.Pid) << ")\n";
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
        auto exe = m_vmi->getFromDisk(mod->Path, mod->Name, true);
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

    logLibraryCall(state, *currentMod.get(), *mod.get(), pc, targetAddr, sourceType, exportName);
    onLibraryCall.emit(state, *mod, targetAddr);
}

} // namespace plugins
} // namespace s2e
