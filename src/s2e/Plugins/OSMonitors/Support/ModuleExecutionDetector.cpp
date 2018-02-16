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
                  "OSMonitor", "Vmi");

ModuleExecutionDetector::~ModuleExecutionDetector() {
}

void ModuleExecutionDetector::initialize() {
    m_Monitor = (OSMonitor *) s2e()->getPlugin("OSMonitor");
    assert(m_Monitor);

    m_vmi = s2e()->getPlugin<Vmi>();

    m_Monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::moduleLoadListener));

    m_Monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::moduleUnloadListener));

    m_Monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::processUnloadListener));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockEnd));

    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockComplete));

    s2e()->getCorePlugin()->onException.connect(sigc::mem_fun(*this, &ModuleExecutionDetector::exceptionListener));

    s2e()->getCorePlugin()->onCustomInstruction.connect(
        sigc::mem_fun(*this, &ModuleExecutionDetector::onCustomInstruction));

    initializeConfiguration();
}

void ModuleExecutionDetector::initializeConfiguration() {
    ConfigFile *cfg = s2e()->getConfig();

    ConfigFile::string_list keyList = cfg->getListKeys(getConfigKey());

    if (keyList.size() == 0) {
        getWarningsStream() << "ModuleExecutionDetector: no configuration keys!" << '\n';
    }

    m_TrackAllModules = cfg->getBool(getConfigKey() + ".trackAllModules");
    m_ConfigureAllModules = cfg->getBool(getConfigKey() + ".configureAllModules");

    m_TrackExecution = cfg->getBool(getConfigKey() + ".trackExecution", true);

    unsigned moduleIndex = 0;
    foreach2 (it, keyList.begin(), keyList.end()) {
        if (*it == "trackAllModules" || *it == "configureAllModules" || *it == "trackExecution") {
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

        getDebugStream() << "ModuleExecutionDetector: "
                         << "id=" << d.id << " "
                         << "moduleName=" << d.moduleName << " "
                         << "context=" << d.context << '\n';

        if (m_ConfiguredModulesName.find(d) != m_ConfiguredModulesName.end()) {
            getWarningsStream() << "ModuleExecutionDetector: "
                                << "module names must be unique!" << '\n';
            exit(-1);
        }

        if (m_ConfiguredModulesId.find(d) != m_ConfiguredModulesId.end()) {
            getWarningsStream() << "ModuleExecutionDetector: "
                                << "module ids must be unique!" << '\n';
            exit(-1);
        }

        m_ConfiguredModulesId.insert(d);
        m_ConfiguredModulesName.insert(d);
    }
}
/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/
bool ModuleExecutionDetector::opAddModuleConfigEntry(S2EExecutionState *state) {
    bool ok = true;
    // XXX: 32-bits guests only
    target_ulong moduleId, moduleName, isKernelMode;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &moduleId, sizeof(moduleId));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &moduleName, sizeof(moduleName));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]), &isKernelMode, sizeof(isKernelMode));

    if (!ok) {
        getWarningsStream(state) << "Could not read parameters\n";
        return false;
    }

    std::string strModuleId, strModuleName;
    if (!state->mem()->readString(moduleId, strModuleId)) {
        getWarningsStream(state) << "Could not read the module id string\n";
        return false;
    }

    if (!state->mem()->readString(moduleName, strModuleName)) {
        getWarningsStream(state) << "Could not read the module name string\n";
        return false;
    }

    ModuleExecutionCfg desc;
    desc.id = strModuleId;
    desc.moduleName = strModuleName;
    desc.kernelMode = (bool) isKernelMode;

    getInfoStream() << "ModuleExecutionDetector: Adding module "
                    << "id=" << desc.id << " moduleName=" << desc.moduleName << " kernelMode=" << desc.kernelMode
                    << "\n";

    if (m_ConfiguredModulesName.find(desc) != m_ConfiguredModulesName.end()) {
        getWarningsStream() << "ModuleExecutionDetector: "
                            << "module name " << desc.moduleName << " already exists\n";
        return false;
    }

    if (m_ConfiguredModulesId.find(desc) != m_ConfiguredModulesId.end()) {
        getWarningsStream() << "ModuleExecutionDetector: "
                            << "module id " << desc.id << " already exists\n";
        return false;
    }

    m_ConfiguredModulesId.insert(desc);
    m_ConfiguredModulesName.insert(desc);

    return true;
}

void ModuleExecutionDetector::onCustomInstruction(S2EExecutionState *state, uint64_t operand) {
    if (!OPCODE_CHECK(operand, MODULE_EXECUTION_DETECTOR_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(operand);

    switch (subfunction) {
        case 0: {
            if (opAddModuleConfigEntry(state)) {
                if (s2e()->getExecutor()->getStatesCount() > 1) {
                    getWarningsStream(state)
                        << "ModuleExecutionDetector attempts to flush the TB cache while having more than 1 state.\n"
                        << "Doing that in S2E is dangerous for many reasons, so we ignore the request.\n";
                } else {
                    tb_flush(env);
                }

                state->setPc(state->getPc() + OPCODE_SIZE);
                throw CpuExitException();
            }
            break;
        }
    }
}

void ModuleExecutionDetector::handleOpcodeGetModule(S2EExecutionState *state, uint64_t guestDataPtr,
                                                    S2E_MODEX_DETECTOR_COMMAND command) {
    const ModuleDescriptor *module = getModule(state, command.Module.AbsoluteAddress, false);
    if (!module) {
        return;
    }

    command.Module.NativeBaseAddress = module->ToNativeBase(command.Module.AbsoluteAddress);

    if (command.Module.ModuleName && command.Module.ModuleNameSize > 0) {
        std::string moduleName = module->Name;
        int size = std::min(moduleName.length() + 1, command.Module.ModuleNameSize);

        if (size > 0) {
            state->mem()->writeMemoryConcrete(command.Module.ModuleName, moduleName.c_str(), size);
        }
    }

    state->mem()->writeMemoryConcrete(guestDataPtr, &command, sizeof(command));
}

void ModuleExecutionDetector::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                     uint64_t guestDataSize) {
    S2E_MODEX_DETECTOR_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "ModuleExecutionDetector: mismatched S2E_MODEX_DETECTOR_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "ModuleExecutionDetector: could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case GET_MODULE: {
            handleOpcodeGetModule(state, guestDataPtr, command);
        } break;

        default: {
            getInfoStream(state) << "ModuleExecutionDetector: "
                                 << "Invalid command " << hexval(command.Command) << "\n";
        }
    }
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    // If module name matches the configured ones, activate.
    getDebugStream(state) << "Module " << module.Name << " loaded - "
                          << "Base=" << hexval(module.LoadBase) << " NativeBase=" << hexval(module.NativeBase)
                          << " Size=" << hexval(module.Size) << " AS=" << hexval(module.AddressSpace) << "\n";

    ModuleExecutionCfg cfg;
    cfg.moduleName = module.Name;

    if (m_ConfigureAllModules) {
        if (plgState->exists(&module, true)) {
            getWarningsStream(state) << " [ALREADY REGISTERED] " << module.Name << "\n";
        } else {
            getDebugStream(state) << " [REGISTERING]\n";
            plgState->loadDescriptor(module, true);
            onModuleLoad.emit(state, module);
        }
        return;
    }

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it != m_ConfiguredModulesName.end()) {
        if (plgState->exists(&module, true)) {
            getDebugStream(state) << " [ALREADY REGISTERED ID=" << it->id << "]" << '\n';
        } else {
            getDebugStream(state) << " [REGISTERING ID=" << it->id << "]" << '\n';
            plgState->loadDescriptor(module, true);
            onModuleLoad.emit(state, module);
        }
        return;
    }

    getDebugStream(state) << '\n';

    if (m_TrackAllModules) {
        if (!plgState->exists(&module, false)) {
            getDebugStream(state) << " [REGISTERING NOT TRACKED]" << '\n';
            plgState->loadDescriptor(module, false);
            onModuleLoad.emit(state, module);
        }
        return;
    }
}

void ModuleExecutionDetector::moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    getDebugStream(state) << "Module " << module.Name << " is unloaded" << '\n';

    plgState->unloadDescriptor(module);
}

void ModuleExecutionDetector::processUnloadListener(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid,
                                                    uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    getDebugStream(state) << "Process " << hexval(addressSpace) << " (pid=" << hexval(pid) << ") is unloaded\n";

    plgState->unloadDescriptor(pid);
}

// Check that the module id is valid
bool ModuleExecutionDetector::isModuleConfigured(const std::string &moduleId) const {
    ModuleExecutionCfg cfg;
    cfg.id = moduleId;

    return m_ConfiguredModulesId.find(cfg) != m_ConfiguredModulesId.end();
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

const ModuleDescriptor *ModuleExecutionDetector::getModule(S2EExecutionState *state, uint64_t pc, bool tracked) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);
    uint64_t addressSpace = m_Monitor->getAddressSpace(state, pc);

    const ModuleDescriptor *currentModule = plgState->getDescriptor(addressSpace, pc, tracked);
    return currentModule;
}

const ModuleDescriptor *ModuleExecutionDetector::getModule(S2EExecutionState *state, uint64_t addressSpace, uint64_t pc,
                                                           bool tracked) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    const ModuleDescriptor *currentModule = plgState->getDescriptor(addressSpace, pc, tracked);
    return currentModule;
}

const ModuleDescriptor *ModuleExecutionDetector::getModule(S2EExecutionState *state, const std::string &moduleName,
                                                           bool tracked) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);
    const ModuleDescriptor *currentModule = plgState->getDescriptor(moduleName, tracked);
    return currentModule;
}

const std::string *ModuleExecutionDetector::getModuleId(const ModuleDescriptor &desc, unsigned *index) const {
    ModuleExecutionCfg cfg;
    cfg.moduleName = desc.Name;

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it == m_ConfiguredModulesName.end()) {
        return NULL;
    }

    if (index) {
        *index = it->index;
    }

    return &(it->id);
}

std::vector<const ModuleDescriptor *> ModuleExecutionDetector::getModules(S2EExecutionState *state,
                                                                          uint64_t addressSpace, bool tracked) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);
    std::vector<const ModuleDescriptor *> modules;

    foreach2 (it, plgState->m_Descriptors.begin(), plgState->m_Descriptors.end()) {
        if ((*it)->AddressSpace == addressSpace)
            modules.push_back(*it);
    }

    if (!tracked) {
        foreach2 (it, plgState->m_NotTrackedDescriptors.begin(), plgState->m_NotTrackedDescriptors.end()) {
            if ((*it)->AddressSpace == addressSpace)
                modules.push_back(*it);
        }
    }

    return modules;
}

void ModuleExecutionDetector::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    uint64_t addressSpace = m_Monitor->getAddressSpace(state, pc);

    const ModuleDescriptor *currentModule = plgState->getDescriptor(addressSpace, pc);

    if (currentModule) {
        // S2E::printf(getDebugStream(), "Translating block %#"PRIx64" belonging to %s\n",pc,
        // currentModule->Name.c_str());
        if (m_TrackExecution) {
            signal->connect(sigc::mem_fun(*this, &ModuleExecutionDetector::onExecution));
        }

        onModuleTranslateBlockStart.emit(signal, state, *currentModule, tb, pc);
    }
}

void ModuleExecutionDetector::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  TranslationBlock *tb, uint64_t endPc, bool staticTarget,
                                                  uint64_t targetPc) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    const ModuleDescriptor *currentModule = getCurrentDescriptor(state);

    if (!currentModule) {
        // Outside of any module, do not need
        // to instrument tb exits.
        return;
    }

    if (m_TrackExecution) {
        if (staticTarget) {
            const ModuleDescriptor *targetModule =
                plgState->getDescriptor(m_Monitor->getAddressSpace(state, targetPc), targetPc);

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
    const ModuleDescriptor *currentModule = getCurrentDescriptor(state);

    if (!currentModule) {
        return;
    }

    onModuleTranslateBlockComplete.emit(state, *currentModule, tb, pc);
}

void ModuleExecutionDetector::exceptionListener(S2EExecutionState *state, unsigned intNb, uint64_t pc) {
    // std::cout << "Exception index " << intNb << '\n';
    // onExecution(state, pc);

    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    // gTRACE("addressSpace=%#"PRIx64" pc=%#"PRIx64"\n", pid, pc);
    if (plgState->m_PreviousModule != NULL) {
        onModuleTransition.emit(state, plgState->m_PreviousModule, NULL);
        plgState->m_PreviousModule = NULL;
    }
}

/**
 *  This returns the descriptor of the module that is currently being executed.
 *  This works only when tracking of all modules is activated.
 */
const ModuleDescriptor *ModuleExecutionDetector::getCurrentDescriptor(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE_CONST(ModuleTransitionState, state);

    uint64_t pc = state->getPc();
    uint64_t addressSpace = m_Monitor->getAddressSpace(state, pc);

    return plgState->getDescriptor(addressSpace, pc);
}

void ModuleExecutionDetector::onExecution(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleTransitionState, state);

    const ModuleDescriptor *currentModule = getCurrentDescriptor(state);

    // gTRACE("addressSpace=%#"PRIx64" pc=%#"PRIx64"\n", pid, pc);
    if (plgState->m_PreviousModule != currentModule) {
        onModuleTransition.emit(state, plgState->m_PreviousModule, currentModule);

        plgState->m_PreviousModule = currentModule;
    }
}

klee::ref<klee::Expr> ModuleExecutionDetector::readMemory8(S2EExecutionState *state, uint64_t addr) {
    klee::ref<klee::Expr> expr = state->mem()->readMemory8(addr);
    if (!expr.isNull()) {
        return expr;
    }

    /* Try to read data from executable image */

    const ModuleDescriptor *module = getCurrentDescriptor(state);
    if (!module) {
        getDebugStream(state) << "No current module\n";
        return klee::ref<klee::Expr>(NULL);
    }

    uint8_t byte;
    if (!m_vmi->readModuleData(*module, addr, byte)) {
        getDebugStream(state) << "Failed to read memory at address " << hexval(addr) << "\n";
        return klee::ref<klee::Expr>(NULL);
    }

    return klee::ConstantExpr::create(byte, klee::Expr::Int8);
}

klee::ref<klee::Expr> ModuleExecutionDetector::readMemory(S2EExecutionState *state, uint64_t addr,
                                                          klee::Expr::Width width) {
    klee::ref<klee::Expr> expr = state->mem()->readMemory(addr, width);
    if (!expr.isNull()) {
        return expr;
    }

    /* Try to read data from executable image */

    const ModuleDescriptor *module = getCurrentDescriptor(state);
    if (!module) {
        getDebugStream(state) << "No current module\n";
        return klee::ref<klee::Expr>(NULL);
    }

    uintmax_t value = 0;
    for (unsigned i = 0; i < width / CHAR_BIT; i++) {
        uint8_t byte;
        if (!m_vmi->readModuleData(*module, addr + i, byte)) {
            getDebugStream(state) << "Failed to read memory at address " << hexval(addr) << "\n";
            return klee::ref<klee::Expr>(NULL);
        }
        value |= ((uintmax_t) byte) << (i * CHAR_BIT);
    }

    return klee::ConstantExpr::create(value, width);
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

ModuleTransitionState::ModuleTransitionState() {
    m_PreviousModule = NULL;
    m_CachedModule = NULL;
}

ModuleTransitionState::~ModuleTransitionState() {
    foreach2 (it, m_Descriptors.begin(), m_Descriptors.end()) { delete *it; }

    foreach2 (it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) { delete *it; }
}

ModuleTransitionState *ModuleTransitionState::clone() const {
    ModuleTransitionState *ret = new ModuleTransitionState();

    foreach2 (it, m_Descriptors.begin(), m_Descriptors.end()) { ret->m_Descriptors.insert(new ModuleDescriptor(**it)); }

    foreach2 (it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
        assert(*it != m_CachedModule && *it != m_PreviousModule);
        ret->m_NotTrackedDescriptors.insert(new ModuleDescriptor(**it));
    }

    if (m_CachedModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_CachedModule);
        assert(it != ret->m_Descriptors.end());
        ret->m_CachedModule = *it;
    }

    if (m_PreviousModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_PreviousModule);
        assert(it != ret->m_Descriptors.end());
        ret->m_PreviousModule = *it;
    }

    return ret;
}

PluginState *ModuleTransitionState::factory(Plugin *p, S2EExecutionState *state) {
    ModuleTransitionState *s = new ModuleTransitionState();

    p->getDebugStream() << "Creating initial module transition state\n";

    return s;
}

const ModuleDescriptor *ModuleTransitionState::getDescriptor(const std::string &moduleName, bool tracked) const {
    const DescriptorSet &descs = tracked ? m_Descriptors : m_NotTrackedDescriptors;

    foreach2 (it, descs.begin(), descs.end()) {
        if ((*it)->Name == moduleName) {
            return *it;
        }
    }

    return NULL;
}

const ModuleDescriptor *ModuleTransitionState::getDescriptor(uint64_t addressSpace, uint64_t pc, bool tracked) const {
    if (m_CachedModule) {
        const ModuleDescriptor &md = *m_CachedModule;
        uint64_t prevModStart = md.LoadBase;
        uint64_t prevModSize = md.Size;
        uint64_t prevModAddressSpace = md.AddressSpace;
        if (addressSpace == prevModAddressSpace && pc >= prevModStart && pc < prevModStart + prevModSize) {
            // We stayed in the same module
            return m_CachedModule;
        }
    }

    ModuleDescriptor d;
    d.AddressSpace = addressSpace;
    d.LoadBase = pc;
    d.Size = 1;
    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        m_CachedModule = *it;
        return *it;
    }

    m_CachedModule = NULL;

    if (!tracked) {
        it = m_NotTrackedDescriptors.find(&d);
        if (it != m_NotTrackedDescriptors.end()) {
            // XXX: implement proper caching
            assert(*it != m_CachedModule && *it != m_PreviousModule);
            return *it;
        }
    }

    return NULL;
}

bool ModuleTransitionState::loadDescriptor(const ModuleDescriptor &desc, bool track) {
    if (track) {
        m_Descriptors.insert(new ModuleDescriptor(desc));
    } else {
        if (m_NotTrackedDescriptors.find(&desc) == m_NotTrackedDescriptors.end()) {
            m_NotTrackedDescriptors.insert(new ModuleDescriptor(desc));
        } else {
            return false;
        }
    }
    return true;
}

void ModuleTransitionState::unloadDescriptor(const ModuleDescriptor &desc) {
    ModuleDescriptor d;
    d.LoadBase = desc.LoadBase;
    d.AddressSpace = desc.AddressSpace;
    d.Size = desc.Size;

    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        if (m_CachedModule == *it) {
            m_CachedModule = NULL;
        }

        if (m_PreviousModule == *it) {
            m_PreviousModule = NULL;
        }

        const ModuleDescriptor *md = *it;
        size_t s = m_Descriptors.erase(*it);
        assert(s == 1);
        delete md;
    }

    it = m_NotTrackedDescriptors.find(&d);
    if (it != m_NotTrackedDescriptors.end()) {
        assert(*it != m_CachedModule && *it != m_PreviousModule);
        const ModuleDescriptor *md = *it;
        size_t s = m_NotTrackedDescriptors.erase(*it);
        assert(s == 1);
        delete md;
    }
}

void ModuleTransitionState::unloadDescriptor(uint64_t pid) {
    DescriptorSet::iterator it, it1;

    for (it = m_Descriptors.begin(); it != m_Descriptors.end();) {
        if ((*it)->Pid != pid) {
            ++it;
        } else {
            it1 = it;
            ++it1;

            if (m_CachedModule == *it) {
                m_CachedModule = NULL;
            }

            if (m_PreviousModule == *it) {
                m_PreviousModule = NULL;
            }

            const ModuleDescriptor *md = *it;
            m_Descriptors.erase(*it);
            delete md;

            it = it1;
        }
    }

    // XXX: avoid copy/paste
    for (it = m_NotTrackedDescriptors.begin(); it != m_NotTrackedDescriptors.end();) {
        if ((*it)->Pid != pid) {
            ++it;
        } else {
            it1 = it;
            ++it1;

            if (m_CachedModule == *it) {
                m_CachedModule = NULL;
            }

            if (m_PreviousModule == *it) {
                m_PreviousModule = NULL;
            }

            const ModuleDescriptor *md = *it;
            m_NotTrackedDescriptors.erase(*it);
            delete md;

            it = it1;
        }
    }
}

bool ModuleTransitionState::exists(const ModuleDescriptor *desc, bool tracked) const {
    bool ret;
    ret = m_Descriptors.find(desc) != m_Descriptors.end();
    if (ret) {
        return ret;
    }

    if (tracked) {
        return false;
    }

    return m_NotTrackedDescriptors.find(desc) != m_NotTrackedDescriptors.end();
}
