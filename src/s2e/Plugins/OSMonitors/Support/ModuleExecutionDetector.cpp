///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/**
 *  This plugin tracks the modules which are being executed at any given point.
 *  A module is a piece of code defined by a name. Currently the pieces of code
 *  are derived from the actual executable files reported by the OS monitor.
 *  TODO: allow specifying any kind of regions.
 *
 *  XXX: distinguish between processes and libraries, which should be tracked in all processes.
 *
 *  XXX: might translate a block without instrumentation and reuse it in instrumented part...
 *
 *  NOTE: it is not possible to track relationships between modules here.
 *  For example, tracking of a library of a particular process. Instead, the
 *  plugin tracks all libraries in all processes. This is because the instrumented
 *  code can be shared between different processes. We have to conservatively instrument
 *  all code, otherwise if some interesting code is translated first within the context
 *  of an irrelevant process, there would be no detection instrumentation, and when the
 *  code is executed in the relevant process, the module execution detection would fail.
 */
//#define NDEBUG

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>

#include <assert.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <sstream>

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(ModuleExecutionDetector, "Plugin for monitoring module execution", "ModuleExecutionDetector",
                  "ModuleMap", "OSMonitor", "Vmi");

ModuleExecutionDetector::~ModuleExecutionDetector() {
}

void ModuleExecutionDetector::initialize() {
    m_monitor = (OSMonitor *) s2e()->getPlugin("OSMonitor");
    assert(m_monitor);

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

    m_trackAllModules = cfg->getBool(getConfigKey() + ".trackAllModules");
    m_configureAllModules = cfg->getBool(getConfigKey() + ".configureAllModules");
    m_trackExecution = cfg->getBool(getConfigKey() + ".trackExecution", false);

    if (m_trackExecution) {
        // TODO: this is temporary
        getWarningsStream() << "Tracking module execution is not supported yet\n";
        exit(-1);
    }

    // TODO: get rid of all this stuff eventually (e.g., we don't need kernelMode anymore).
    // Plugin should primarily use ModuleMap.
    unsigned moduleIndex = 0;
    foreach2 (it, keyList.begin(), keyList.end()) {
        if (*it == "trackAllModules" || *it == "configureAllModules" || *it == "trackExecution" || *it == "logLevel") {
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

        d.kernelMode = cfg->getBool(s.str() + "kernelMode", false, &ok);
        if (!ok) {
            getWarningsStream() << "You must specifiy " << s.str() + "kernelMode" << '\n';
            exit(-1);
        }

        getDebugStream() << "id=" << d.id << " "
                         << "moduleName=" << d.moduleName << " "
                         << "context=" << d.context << '\n';

        if (exists(d.id, d.moduleName)) {
            getWarningsStream() << "module with id " << d.id << " or name " << d.moduleName << " already exists"
                                << '\n';
            exit(-1);
        }

        m_configuredModules.insert(d);
    }
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    // If module name matches the configured ones, activate.
    getDebugStream(state) << "module loaded: " << module << "\n";

    if (m_configureAllModules) {
        getInfoStream(state) << "loading " << module.Name << "\n";
        onModuleLoad.emit(state, module);
        return;
    }

    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    const auto it = byName.find(module.Name);
    if (it != byName.end()) {
        getInfoStream(state) << "loading id " << it->id << "\n";
        onModuleLoad.emit(state, module);
        return;
    }

    if (m_trackAllModules) {
        getDebugStream(state) << "registering " << module.Name << " (tracking all modules)\n";
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
        signal->connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution));
    }

    onModuleTranslateBlockStart.emit(signal, state, *currentModule, tb, pc);
}

void ModuleExecutionDetector::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t endPc, bool staticTarget,
                                                  uint64_t targetPc) {
    auto currentModule = getCurrentDescriptor(state);
    if (!currentModule) {
        // Outside of any module, do not need to instrument tb exits.
        return;
    }

    if (m_trackExecution) {
        if (staticTarget) {
            auto targetModule = getDescriptor(state, targetPc);

            if (targetModule != currentModule) {
                // Only instrument in case there is a module change
                // TRACE("Static transition from %#"PRIx64" to %#"PRIx64"\n",
                //    endPc, targetPc);
                signal->connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution));
            }
        } else {
            // TRACE("Dynamic transition from %#"PRIx64" to %#"PRIx64"\n",
            //        endPc, targetPc);
            // In case of dynamic targets, conservatively
            // instrument code.
            signal->connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution));
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

    if (plgState->m_previousModule != nullptr) {
        onModuleTransition.emit(state, plgState->m_previousModule, nullptr);
        plgState->m_previousModule = nullptr;
    }
}

void ModuleExecutionDetector::onExecution(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    auto currentModule = getCurrentDescriptor(state);

    if (plgState->m_previousModule != currentModule) {
        plgState->m_previousModule = currentModule;
        onModuleTransition.emit(state, plgState->m_previousModule, currentModule);
    }
}

ModuleDescriptorConstPtr ModuleExecutionDetector::getModule(S2EExecutionState *state, uint64_t pc) {
    return getDescriptor(state, pc);
}

const std::string *ModuleExecutionDetector::getModuleId(const ModuleDescriptor &desc, unsigned *index) const {
    const ConfiguredModulesByName &byName = m_configuredModules.get<modbyname_t>();
    const auto it = byName.find(desc.Name);
    if (it == byName.end()) {
        return NULL;
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

    if (m_configureAllModules || isModuleNameConfigured(module->Name)) {
        return module;
    }

    return nullptr;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

ModuleTransitionState::ModuleTransitionState() {
    m_previousModule = nullptr;
}

ModuleTransitionState::~ModuleTransitionState() {
}

ModuleTransitionState *ModuleTransitionState::clone() const {
    return new ModuleTransitionState(*this);
}

PluginState *ModuleTransitionState::factory(Plugin *p, S2EExecutionState *state) {
    return new ModuleTransitionState();
}
