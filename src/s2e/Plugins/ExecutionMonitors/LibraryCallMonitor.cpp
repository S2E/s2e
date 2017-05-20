///
/// Copyright (C) 2011-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <iostream>

#include "LibraryCallMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LibraryCallMonitor, "Flags all calls to external libraries", "LibraryCallMonitor", "OSMonitor",
                  "FunctionMonitor", "ModuleExecutionDetector", "Vmi");

void LibraryCallMonitor::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_functionMonitor = s2e()->getPlugin<FunctionMonitor>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    ConfigFile *cfg = s2e()->getConfig();
    m_displayOnce = cfg->getBool(getConfigKey() + ".displayOnce", false);

    bool ok = false;

    // Fetch the list of modules where to report the calls
    ConfigFile::string_list moduleList =
        cfg->getStringList(getConfigKey() + ".moduleIds", ConfigFile::string_list(), &ok);

    if (!ok || moduleList.empty()) {
        getWarningsStream() << "no modules specified, tracking everything.\n";
    }

    foreach2 (it, moduleList.begin(), moduleList.end()) {
        if (!m_detector->isModuleConfigured(*it)) {
            getWarningsStream() << "module " << *it << " is not configured\n";
            exit(-1);
        }
        m_trackedModules.insert(*it);
    }

    m_detector->onModuleLoad.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onModuleLoad));

    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &LibraryCallMonitor::onModuleUnload));
}

void LibraryCallMonitor::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    vmi::Imports imports;

    if (!m_vmi->getImports(state, module, imports)) {
        getWarningsStream() << "could not retrieve imported functions in " << module.Name << '\n';
        return;
    }

    // Unless otherwise specified, LibraryCallMonitor tracks all library calls in the system
    if (!m_trackedModules.empty()) {
        const std::string *moduleId = m_detector->getModuleId(module);
        if (!moduleId || (m_trackedModules.find(*moduleId) == m_trackedModules.end())) {
            return;
        }
    }

    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);

    foreach2 (it, imports.begin(), imports.end()) {
        const std::string &libName = (*it).first;
        const vmi::ImportedSymbols &funcs = (*it).second;
        foreach2 (fit, funcs.begin(), funcs.end()) {
            const std::string &funcName = (*fit).first;
            std::string composedName = libName + "!";
            composedName = composedName + funcName;

            uint64_t address = (*fit).second.address;

            std::pair<StringSet::iterator, bool> insertRes;
            insertRes = m_functionNames.insert(composedName);

            const char *cstring = (*insertRes.first).c_str();
            plgState->m_functions[address] = cstring;

            FunctionMonitor::CallSignal *cs = m_functionMonitor->getCallSignal(state, address, module.AddressSpace);
            cs->connect(sigc::mem_fun(*this, &LibraryCallMonitor::onFunctionCall));
        }
    }
}

void LibraryCallMonitor::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    m_functionMonitor->disconnect(state, module);
    return;
}

void LibraryCallMonitor::onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    // Only track configured modules
    uint64_t caller = state->getTb()->pcOfLastInstr;
    const ModuleDescriptor *mod = m_detector->getModule(state, caller);
    if (!mod) {
        return;
    }

    DECLARE_PLUGINSTATE(LibraryCallMonitorState, state);
    uint64_t pc = state->getPc();

    if (m_displayOnce &&
        (m_alreadyCalledFunctions.find(std::make_pair(mod->AddressSpace, pc)) != m_alreadyCalledFunctions.end())) {
        return;
    }

    LibraryCallMonitorState::AddressToFunctionName::iterator it = plgState->m_functions.find(pc);
    if (it != plgState->m_functions.end()) {
        const char *str = (*it).second;
        getInfoStream() << mod->Name << "@" << hexval(mod->ToNativeBase(caller)) << " called function " << str << '\n';

        onLibraryCall.emit(state, fns, *mod);

        if (m_displayOnce) {
            m_alreadyCalledFunctions.insert(std::make_pair(mod->AddressSpace, pc));
        }
    }
}

LibraryCallMonitorState::LibraryCallMonitorState() {
}

LibraryCallMonitorState::~LibraryCallMonitorState() {
}

LibraryCallMonitorState *LibraryCallMonitorState::clone() const {
    return new LibraryCallMonitorState(*this);
}

PluginState *LibraryCallMonitorState::factory(Plugin *p, S2EExecutionState *s) {
    return new LibraryCallMonitorState();
}

} // namespace plugins
} // namespace s2e
