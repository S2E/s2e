///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __MODULE_EXECUTION_DETECTOR_H_

#define __MODULE_EXECUTION_DETECTOR_H_

#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>

#include <inttypes.h>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace s2e {
namespace plugins {

class OSMonitor;

/**
 *  Module description from configuration file
 */
struct ModuleExecutionCfg {
    unsigned index;
    std::string id;
    std::string moduleName;
    bool kernelMode;
    std::string context;
};

struct modbyid_t {};
struct modbyname_t {};

typedef boost::multi_index_container<
    ModuleExecutionCfg,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<modbyid_t>,
                                           BOOST_MULTI_INDEX_MEMBER(ModuleExecutionCfg, std::string, id)>,
        boost::multi_index::ordered_unique<boost::multi_index::tag<modbyname_t>,
                                           BOOST_MULTI_INDEX_MEMBER(ModuleExecutionCfg, std::string, moduleName)>>>
    ConfiguredModules;

typedef ConfiguredModules::index<modbyid_t>::type ConfiguredModulesById;
typedef ConfiguredModules::index<modbyname_t>::type ConfiguredModulesByName;

class ModuleExecutionDetector : public Plugin {
    S2E_PLUGIN

public:
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor *, const ModuleDescriptor *> onModuleTransition;

    /** Signal that is emitted on beginning and end of code generation
        for each translation block belonging to the module.
    */
    sigc::signal<void, ExecutionSignal *, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* block PC */>
        onModuleTranslateBlockStart;

    /** Signal that is emitted upon end of translation block of the module */
    sigc::signal<void, ExecutionSignal *, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* ending instruction pc */, bool /* static target is valid */,
                 uint64_t /* static target pc */>
        onModuleTranslateBlockEnd;

    /**
     * Signal that is emitted when the translator finishes
     * translating the block.
     */
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* ending instruction pc */>
        onModuleTranslateBlockComplete;

    /** This filters module loads passed by OSInterceptor */
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &> onModuleLoad;

private:
    OSMonitor *m_monitor;
    Vmi *m_vmi;
    ModuleMap *m_modules;
    ConfiguredModules m_configuredModules;

    bool m_trackAllModules;
    bool m_configureAllModules;

    bool m_trackExecution;

    void initializeConfiguration();

    void onMonitorLoad(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc,
                             bool staticTarget, uint64_t targetPc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onExecution(S2EExecutionState *state, uint64_t pc);

    void exceptionListener(S2EExecutionState *state, unsigned intNb, uint64_t pc);

    void moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module);

    bool exists(const std::string &id, const std::string &name) const {
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

public:
    ModuleExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }
    virtual ~ModuleExecutionDetector();

    void initialize();

    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t pc);
    const ModuleDescriptor *getCurrentDescriptor(S2EExecutionState *state) const;
    const ModuleDescriptor *getDescriptor(S2EExecutionState *state, uint64_t pc) const;
    const std::string *getModuleId(const ModuleDescriptor &desc, unsigned *index = NULL) const;

    bool getModuleConfig(const std::string &id, ModuleExecutionCfg &cfg) const {
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

    bool isModuleConfigured(const std::string &moduleId) const;
    bool isModuleNameConfigured(const std::string &moduleName) const;
    bool trackAllModules() const {
        return m_trackAllModules;
    }
};

class ModuleTransitionState : public PluginState {
public:
    // XXX: until we use shared_ptr, this will not work and we can't
    // track module execution.
    const ModuleDescriptor *m_previousModule;

    ModuleTransitionState();
    virtual ~ModuleTransitionState();
    virtual ModuleTransitionState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);
};

} // namespace plugins
} // namespace s2e

#endif
