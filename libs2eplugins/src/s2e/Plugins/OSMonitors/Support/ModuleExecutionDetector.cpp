///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>

#include <assert.h>
#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleExecutionDetector, "Plugin for monitoring module execution", "ModuleExecutionDetector",
                  "ModuleMap", "OSMonitor", "Vmi");

namespace {
class ModuleTransitionState : public PluginState {
public:
    ModuleDescriptorConstPtr m_previousModule;

    ModuleTransitionState() : m_previousModule(nullptr) {
    }
    virtual ~ModuleTransitionState() {
    }
    virtual ModuleTransitionState *clone() const {
        return new ModuleTransitionState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ModuleTransitionState();
    }
};
} // namespace

void ModuleExecutionDetector::initialize() {
    m_monitor = (OSMonitor *) s2e()->getPlugin("OSMonitor");
    m_modules = s2e()->getPlugin<ModuleMap>();
    m_vmi = s2e()->getPlugin<Vmi>();

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onMonitorLoad));

    initializeConfiguration();
}

void ModuleExecutionDetector::onMonitorLoad(S2EExecutionState *state) {
    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::moduleLoadListener));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockComplete));

    s2e()->getCorePlugin()->onException.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::exceptionListener));
}

void ModuleExecutionDetector::initializeConfiguration() {
    ConfigFile *cfg = s2e()->getConfig();

    ConfigFile::string_list keyList = cfg->getListKeys(getConfigKey());

    if (keyList.size() == 0) {
        getWarningsStream() << "no configuration keys!" << '\n';
    }

    m_trackExecution = cfg->getBool(getConfigKey() + ".trackExecution", true);

    unsigned moduleIndex = 0;

    foreach2 (it, keyList.begin(), keyList.end()) {
        if (*it == "trackExecution" || *it == "logLevel") {
            continue;
        }

        ModuleExecutionCfg d;
        std::stringstream s;
        s << getConfigKey() << "." << *it << ".";
        d.id = *it;
        d.index = moduleIndex++;

        bool ok = false;
        d.moduleName = cfg->getString(s.str() + "moduleName", "", &ok);
        if (!ok) {
            getWarningsStream() << "You must specifiy " << s.str() + "moduleName" << '\n';
            exit(-1);
        }

        getDebugStream() << "id=" << d.id << " "
                         << "moduleName=" << d.moduleName << "\n";

        if (exists(d.id, d.moduleName)) {
            getWarningsStream() << "module with id " << d.id << " or name " << d.moduleName << " already exists"
                                << '\n';
            exit(-1);
        }

        m_configuredModules.insert(d);
    }
}

bool ModuleExecutionDetector::exists(const std::string &id, const std::string &name) const {
    const ConfiguredModulesById &byId = m_configuredModules.get<modbyid_t>();
    if (byId.find(id) != byId.end()) {
        return true;
    }

    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    if (byName.find(name) != byName.end()) {
        return true;
    }

    return false;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    // If module name matches the configured ones, activate.
    getDebugStream(state) << "module loaded: " << module << "\n";

    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    const auto it = byName.find(module.Name);
    if (it != byName.end()) {
        getInfoStream(state) << "loading id " << it->id << "\n";
        onModuleLoad.emit(state, module);
        return;
    }
}

// Check that the module id is valid
bool ModuleExecutionDetector::isModuleConfigured(const std::string &moduleId) const {
    const ConfiguredModulesById &byId = m_configuredModules.get<modbyid_t>();
    return byId.find(moduleId) != byId.end();
}

bool ModuleExecutionDetector::isModuleNameConfigured(const std::string &moduleName) const {
    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    return byName.find(moduleName) != byName.end();
}

bool ModuleExecutionDetector::getModuleConfig(const std::string &id, ModuleExecutionCfg &cfg) const {
    ModuleExecutionCfg tofind;
    tofind.id = id;

    const ConfiguredModulesById &byId = m_configuredModules.get<modbyid_t>();

    ConfiguredModulesById::const_iterator it = byId.find(id);
    if (it == byId.end()) {
        return false;
    }

    cfg = *it;
    return true;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc) {

    auto currentModule = getDescriptor(state, pc);
    if (!currentModule) {
        return;
    }

    if (m_trackExecution) {
        signal->connect(sigc::bind(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution), currentModule));
    }

    onModuleTranslateBlockStart.emit(signal, state, *currentModule, tb, pc);
}

void ModuleExecutionDetector::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t endPc, bool staticTarget,
                                                  uint64_t targetPc) {
    auto currentModule = getCurrentDescriptor(state);
    if (!currentModule) {
        return;
    }

    if (m_trackExecution) {
        if (staticTarget) {
            auto targetModule = getDescriptor(state, targetPc);

            if (targetModule != currentModule) {
                signal->connect(sigc::bind(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution), currentModule));
            }
        } else {
            signal->connect(sigc::bind(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution), currentModule));
        }
    }

    if (currentModule) {
        onModuleTranslateBlockEnd.emit(signal, state, *currentModule, tb, endPc, staticTarget, targetPc);
    }
}

void ModuleExecutionDetector::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    auto currentModule = getCurrentDescriptor(state);
    if (!currentModule) {
        return;
    }

    onModuleTranslateBlockComplete.emit(state, *currentModule, tb, pc);
}

void ModuleExecutionDetector::exceptionListener(S2EExecutionState *state, unsigned intNb, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    if (plgState->m_previousModule) {
        onModuleTransition.emit(state, plgState->m_previousModule, nullptr);
        plgState->m_previousModule = nullptr;
    }
}

void ModuleExecutionDetector::onExecution(S2EExecutionState *state, uint64_t pc,
                                          ModuleDescriptorConstPtr currentModule) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    if (plgState->m_previousModule != currentModule) {
        onModuleTransition.emit(state, plgState->m_previousModule, currentModule);
        plgState->m_previousModule = currentModule;
    }
}

ModuleDescriptorConstPtr ModuleExecutionDetector::getModule(S2EExecutionState *state, uint64_t pc) {
    return getDescriptor(state, pc);
}

const std::string *ModuleExecutionDetector::getModuleId(const ModuleDescriptor &desc, unsigned *index) const {
    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    const auto it = byName.find(desc.Name);
    if (it == byName.end()) {
        return nullptr;
    }

    if (index) {
        *index = it->index;
    }

    return &(it->id);
}

/**
 *  This returns the descriptor of the module that is currently being executed.
 *  This works only when tracking of all modules is activated.
 */
ModuleDescriptorConstPtr ModuleExecutionDetector::getCurrentDescriptor(S2EExecutionState *state) const {
    return getDescriptor(state, state->regs()->getPc());
}

ModuleDescriptorConstPtr ModuleExecutionDetector::getDescriptor(S2EExecutionState *state, uint64_t pc) const {
    auto module = m_modules->getModule(state, pc);
    if (!module) {
        return nullptr;
    }

    if (isModuleNameConfigured(module->Name)) {
        return module;
    }

    return nullptr;
}

} // namespace plugins
} // namespace s2e
