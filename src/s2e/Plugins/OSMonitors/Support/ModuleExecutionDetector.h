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

#include <inttypes.h>

namespace s2e {
namespace plugins {

class OSMonitor;

struct S2E_MODEX_MODULE {
    /**
     * IN: absolute address which we want
     * to convert to a module name and a relative address.
     */
    uint64_t AbsoluteAddress;

    /* IN: number of bytes in ModuleName */
    uint64_t ModuleNameSize;

    /* OPTIONAL IN/OUT: pointer to to the module name in guest space */
    uint64_t ModuleName;

    /* OUT: the computed address relative to the module's native base */
    uint64_t NativeBaseAddress;
};

enum S2E_MODEX_DETECTOR_COMMANDS { GET_MODULE };

/**
 * Structure to invoke ModuleExecutionDetector form guest code.
 */
struct S2E_MODEX_DETECTOR_COMMAND {
    S2E_MODEX_DETECTOR_COMMANDS Command;
    union {
        S2E_MODEX_MODULE Module;
    };
};

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

struct ModuleExecCfgById {
    bool operator()(const ModuleExecutionCfg &d1, const ModuleExecutionCfg &d2) const {
        // return d1.compare(d2.id) < 0;
        return d1.id < d2.id;
    }
};

struct ModuleExecCfgByName {
    bool operator()(const ModuleExecutionCfg &d1, const ModuleExecutionCfg &d2) const {
        return d1.moduleName < d2.moduleName;
    }
};

typedef std::set<ModuleExecutionCfg, ModuleExecCfgById> ConfiguredModulesById;
typedef std::set<ModuleExecutionCfg, ModuleExecCfgByName> ConfiguredModulesByName;

class ModuleExecutionDetector : public Plugin, public BaseInstructionsPluginInvokerInterface {
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
    OSMonitor *m_Monitor;
    Vmi *m_vmi;

    ConfiguredModulesById m_ConfiguredModulesId;
    ConfiguredModulesByName m_ConfiguredModulesName;

    bool m_TrackAllModules;
    bool m_ConfigureAllModules;

    bool m_TrackExecution;

    void initializeConfiguration();
    bool opAddModuleConfigEntry(S2EExecutionState *state);

    void onCustomInstruction(S2EExecutionState *state, uint64_t operand);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc,
                             bool staticTarget, uint64_t targetPc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onExecution(S2EExecutionState *state, uint64_t pc);

    void exceptionListener(S2EExecutionState *state, unsigned intNb, uint64_t pc);

    void moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module);

    void moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &desc);

    void processUnloadListener(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);

    void handleOpcodeGetModule(S2EExecutionState *state, uint64_t guestDataPtr, S2E_MODEX_DETECTOR_COMMAND command);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

public:
    ModuleExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }
    virtual ~ModuleExecutionDetector();

    void initialize();

    // bool toExecutionDesc(ModuleExecutionDesc *desc, const ModuleDescriptor *md);
    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t pc, bool tracked = true);
    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t addressSpace, uint64_t pc,
                                      bool tracked = true);
    const ModuleDescriptor *getModule(S2EExecutionState *state, const std::string &moduleName, bool tracked = true);
    const ModuleDescriptor *getCurrentDescriptor(S2EExecutionState *state) const;
    const std::string *getModuleId(const ModuleDescriptor &desc, unsigned *index = NULL) const;

    std::vector<const ModuleDescriptor *> getModules(S2EExecutionState *state, uint64_t addressSpace,
                                                     bool tracked = true);

    bool getModuleConfig(const std::string &id, ModuleExecutionCfg &cfg) const {
        ModuleExecutionCfg tofind;
        tofind.id = id;
        ConfiguredModulesById::const_iterator it = m_ConfiguredModulesId.find(tofind);
        if (it == m_ConfiguredModulesId.end()) {
            return false;
        }

        cfg = *it;
        return true;
    }

    const ConfiguredModulesById &getConfiguredModulesById() const {
        return m_ConfiguredModulesId;
    }

    bool isModuleConfigured(const std::string &moduleId) const;
    bool trackAllModules() const {
        return m_TrackAllModules;
    }

    klee::ref<klee::Expr> readMemory8(S2EExecutionState *state, uint64_t addr);
    klee::ref<klee::Expr> readMemory(S2EExecutionState *state, uint64_t addr, klee::Expr::Width width);

    friend class ModuleTransitionState;
};

class ModuleTransitionState : public PluginState {
private:
    typedef std::set<const ModuleDescriptor *, ModuleDescriptor::ModuleByLoadBase> DescriptorSet;

    const ModuleDescriptor *m_PreviousModule;
    mutable const ModuleDescriptor *m_CachedModule;

    DescriptorSet m_Descriptors;
    DescriptorSet m_NotTrackedDescriptors;

    const ModuleDescriptor *getDescriptor(uint64_t addressSpace, uint64_t pc, bool tracked = true) const;

    /**
     * Get a loaded descriptor by module name. If multiple descriptors have the same name,
     * returns one of them without any particular order
     */
    const ModuleDescriptor *getDescriptor(const std::string &moduleName, bool tracked = true) const;

    bool loadDescriptor(const ModuleDescriptor &desc, bool track);
    void unloadDescriptor(const ModuleDescriptor &desc);
    void unloadDescriptor(uint64_t pid);
    bool exists(const ModuleDescriptor *desc, bool tracked) const;

public:
    sigc::signal<void, S2EExecutionState *,
                 const ModuleDescriptor *, // PreviousModule
                 const ModuleDescriptor *  // NewModule
                 >
        onModuleTransition;

    ModuleTransitionState();
    virtual ~ModuleTransitionState();
    virtual ModuleTransitionState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class ModuleExecutionDetector;
};

} // namespace plugins
} // namespace s2e

#endif
