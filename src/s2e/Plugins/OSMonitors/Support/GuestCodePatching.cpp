///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

extern "C" {
#include <qint.h>
#include <qlist.h>
#include <qstring.h>
}

#include <s2e/ConfigFile.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <vmi/FileProvider.h>
#include <vmi/PEFile.h>

#include <s2e/Plugins/Core/Events.h>
#include "GuestCodePatching.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(GuestCodePatching, "Transparent patching of guest code", "GuestCodePatching", "WindowsMonitor",
                  "ModuleExecutionDetector", "Vmi");

void GuestCodePatching::initialize() {
    // TODO: make the plugin os-agnostic
    m_monitor = s2e()->getPlugin<WindowsMonitor>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_vmi = s2e()->getPlugin<Vmi>();

    ConfigFile *cfg = s2e()->getConfig();

    m_allowSelfCalls = cfg->getBool(getConfigKey() + ".allowSelfCalls");

    ConfigFile::string_list mods = cfg->getStringList(getConfigKey() + ".moduleNames");
    if (mods.size() == 0) {
        getWarningsStream() << "You must specify modules to track in moduleNames" << '\n';
        exit(-1);
        return;
    }

    if (!m_detector->trackAllModules()) {
        getWarningsStream() << "ModuleExecutionDetector should be set to track all modules\n";
        exit(-1);
    }

    foreach2 (it, mods.begin(), mods.end()) { m_drivers.insert(*it); }

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &GuestCodePatching::onModuleLoad));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &GuestCodePatching::onModuleUnload));

    /* For hooking entry points */
    m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this, &GuestCodePatching::onModuleTranslateBlockStart));

    /* For hooking function calls */
    m_detector->onModuleTranslateBlockEnd.connect(sigc::mem_fun(*this, &GuestCodePatching::onModuleTranslateBlockEnd));

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &GuestCodePatching::onTimer));
}

/***********************************************************************/

/**
 * Periodically sends the list of entry points to the service.
 * This can be useful to compute entry point coverage.
 */
void GuestCodePatching::onTimer() {
    if (!monitor_ready()) {
        return;
    }

    if (m_entryPoints.size() > 0) {
        Events::PluginData data;
        data.push_back(std::make_pair("entry_points", getEntryPoints()));
        Events::emitQMPEvent(this, data);
    }
}

QObject *GuestCodePatching::getEntryPoints() {
    QDict *dict = qdict_new();
    foreach2 (it, m_entryPoints.begin(), m_entryPoints.end()) {
        const std::string &moduleName = (*it).first;
        const ModuleEntryPoints &eps = (*it).second;
        QList *entryPoints = qlist_new();
        foreach2 (epit, eps.begin(), eps.end()) {
            const EntryPoint &ep = *epit;
            QDict *entryPoint = qdict_new();
            qdict_put_obj(entryPoint, "name", QOBJECT(qstring_from_str(ep.Name.c_str())));
            qdict_put_obj(entryPoint, "address", QOBJECT(qint_from_int(ep.ModuleAddress)));
            qlist_append(entryPoints, entryPoint);
        }
        qdict_put_obj(dict, moduleName.c_str(), QOBJECT(entryPoints));
    }

    /* The load balancer maintains a list of those */
    m_entryPoints.clear();

    return QOBJECT(dict);
}
/***********************************************************************/

void GuestCodePatching::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    if (m_drivers.find(module.Name) == m_drivers.end()) {
        // Not the right module we want to intercept
        return;
    }

    DECLARE_PLUGINSTATE(GuestCodePatchingState, state);

    // Skip those that were already loaded
    if (plgState->isModuleLoaded(module)) {
        return;
    }

    plgState->loadModule(module);

    patchImports(state, module);

    // XXX: Does this belong to here?
    state->enableSymbolicExecution();
    state->enableForking();
}

void GuestCodePatching::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    if (m_drivers.find(module.Name) == m_drivers.end()) {
        // Not the right module we want to intercept
        return;
    }

    DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
    plgState->unloadModule(module);
    return;
}

//////////////////////////////////////////////////////
void GuestCodePatching::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    DECLARE_PLUGINSTATE(GuestCodePatchingState, state);

    uint64_t hookAddress = plgState->getHookAddress(module, module.ToNativeBase(pc));

    if (hookAddress) {
        // We should connect in front to prevent other plugins
        // from reacting to the interception.
        signal->connect_front(
            sigc::bind(sigc::mem_fun(*this, &GuestCodePatching::onExecuteBlockStart), false, hookAddress));
    } else if (plgState->isDirectKernelHook(pc)) {
        signal->connect_front(sigc::bind(sigc::mem_fun(*this, &GuestCodePatching::onExecuteBlockStart), true,
                                         plgState->getDiectKernelHookAddress(pc)));
    }
}

void GuestCodePatching::invokeHook(S2EExecutionState *state, uint64_t pc, uint64_t hookAddress,
                                   uint64_t returnAddress) {
    uint64_t stackBase = 0, stackSize = 0;
    m_monitor->getCurrentStack(state, &stackBase, &stackSize);

    // Only jump if not coming from the hook itself
    getDebugStream(state) << "jumping to address " << hexval(hookAddress) << " on stack " << hexval(stackBase)
                          << " size=" << hexval(stackSize) << "\n";

    uint64_t pointerSize = state->getPointerSize();
    if (pointerSize == 4) {
        // This assumes stdcall convention, where the callee cleans the stack.
        // This is important, as the annotation gets an extra parameter,
        // which it must clean after it finishes.

        // Push an extra parameter to indicate the target of the real call.
        uint32_t target = pc;
        if (!state->mem()->writeMemoryConcrete(state->getSp(), &target, sizeof(target))) {
            goto err1;
        }

        // The return address goes down one slot
        uint32_t rap = returnAddress;
        if (!state->mem()->writeMemoryConcrete(state->getSp() - pointerSize, &rap, sizeof(rap))) {
            goto err1;
        }

        state->setSp(state->getSp() - pointerSize);

    } else if (pointerSize == 8) {
        DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
        returnAddress = plgState->getEntryPointReturnHook();
        if (!returnAddress) {
            getWarningsStream(state) << "entry point return hook not inited\n";
            goto err1;
        }

        uint64_t origStack = state->regs()->getSp();
        uint64_t origParams = origStack + pointerSize;

        /* Allocate slots for the copied parameters + the original callee's address */
        /* Magic number, won't work if entry point has more than 11 params.
           When changing this number, also update the S2EReturnHook64() stub in s2e.asm */
        unsigned newStackSlots = 11; // 11 + 1 ret addr = 16-bytes alignment

        uint64_t newParams = origStack - newStackSlots * pointerSize;
        uint64_t newStack = newParams - pointerSize; // Return address points to guest stub

        /* Store the initial callee's pc as first parameter of the annotation */
        if (!state->mem()->writeMemoryConcrete(newParams, &pc, sizeof(uint64_t))) {
            goto err1;
        }

        /* Copy up to 11 params of the original function */
        for (unsigned i = 1; i < newStackSlots; ++i) {
            uint64_t param;
            if (!state->mem()->readMemoryConcrete(origParams + (i - 1) * pointerSize, &param, sizeof(param))) {
                goto err1;
            }
            if (!state->mem()->writeMemoryConcrete(newParams + i * pointerSize, &param, sizeof(param))) {
                goto err1;
            }
        }

        // RCX, RDX, R8, and R9 contain the parameters.
        // Shift all params by one slot: RCX=>RDX=>R8=>R9=>stack
        // RCX will get the address of the original function.

        // Stack layout before hooking:
        // RSP: return address
        // RSP + 8: first param, etc.

        uint64_t rcx = state->regs()->read<uint64_t>(offsetof(CPUX86State, regs[R_ECX]));
        uint64_t rdx = state->regs()->read<uint64_t>(offsetof(CPUX86State, regs[R_EDX]));
        uint64_t r8 = state->regs()->read<uint64_t>(offsetof(CPUX86State, regs[8]));
        uint64_t r9 = state->regs()->read<uint64_t>(offsetof(CPUX86State, regs[9]));

        // 1st param becomes the address of the original entry point
        state->regs()->write<uint64_t>(offsetof(CPUX86State, regs[R_ECX]), pc);
        state->regs()->write<uint64_t>(offsetof(CPUX86State, regs[R_EDX]), rcx);
        state->regs()->write<uint64_t>(offsetof(CPUX86State, regs[8]), rdx);
        state->regs()->write<uint64_t>(offsetof(CPUX86State, regs[9]), r8);

        // Spill the last reg on the stack
        if (!state->mem()->writeMemoryConcrete(newParams + 4 * pointerSize, &r9, sizeof(r9))) {
            goto err1;
        }

        // The return hook will clean up the stack
        if (!state->mem()->writeMemoryConcrete(newStack, &returnAddress, sizeof(uint64_t))) {
            goto err1;
        }

        state->setSp(newStack);
    }

    state->setPc(hookAddress);
    throw CpuExitException();

err1:
    s2e()->getExecutor()->terminateStateEarly(*state, "could not setup stack");
}

void GuestCodePatching::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc, bool direct, uint64_t hookAddress) {
    // Get the caller
    uint64_t ra;
    if (!state->getReturnAddress(&ra)) {
        getDebugStream(state) << "could not determine return address\n";
        return;
    }

    const ModuleDescriptor *md = m_detector->getModule(state, ra, false);

    // Prevent infinite recursion.
    if (md->Name.find("s2e.sys") != std::string::npos) {
        return;
    }

    if (direct) {
        state->setPc(hookAddress);
        throw CpuExitException();
    }

    const ModuleDescriptor *currentModule = m_detector->getModule(state, state->getPc());
    if (md == currentModule) {
        if (!m_allowSelfCalls) {
            /**
             * In case the driver calls directly one of its entry points,
             * do nothing. We might destroy registers if we did,
             * if the driver is compiled with whole-program optimizations.
             */
            return;
        }
    }

    invokeHook(state, pc, hookAddress, ra);
}

//////////////////////////////////////////////////////
void GuestCodePatching::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc,
                                                  bool staticTarget, uint64_t targetPc) {
    if (tb->se_tb_type != TB_CALL_IND && tb->se_tb_type != TB_CALL) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &GuestCodePatching::onExecuteCall));
}

void GuestCodePatching::onExecuteCall(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(GuestCodePatchingState, state);

    const ModuleDescriptor *module = m_detector->getModule(state, pc);
    if (!module) {
        return;
    }

    uint64_t hookAddress = plgState->getHookAddress(*module, state->getPc(), true);
    if (!hookAddress) {
        return;
    }

    uint64_t ra;
    if (!state->getReturnAddress(&ra)) {
        getDebugStream(state) << "could not determine return address\n";
        return;
    }

    invokeHook(state, state->getPc(), hookAddress, ra);
}

bool GuestCodePatching::patchImports(S2EExecutionState *state, const ModuleDescriptor &module) {
    vmi::GuestMemoryFileProvider *guestImage =
        new vmi::GuestMemoryFileProvider(state, readMemoryCb, writeMemoryCb, module.Name);

    if (!guestImage) {
        getWarningsStream(state) << "error creating GuestMemoryFileProvider\n";
        return false;
    }

    vmi::PEFile *pe = vmi::PEFile::get(guestImage, true, module.LoadBase);
    if (!pe) {
        getWarningsStream(state) << "could not load memory image for " << module.Name << "\n";
        delete guestImage;
        return false;
    }

    if (pe->getPointerSize() > state->getPointerSize()) {
        getWarningsStream(state) << "image pointer size " << pe->getPointerSize() << " is bigger than the current size "
                                 << state->getPointerSize() << " (" << module.Name
                                 << "). Something is wrong in the OS.\n";

        delete pe;
        delete guestImage;
        return false;
    }

    vmi::Imports imports;
    if (!m_vmi->getImports(state, module, imports)) {
        getDebugStream(state) << "could not find imports\n";
        return false;
    }

    getDebugStream(state) << "loaded " << module.Name << " - Scanning imports - Imported libs: " << imports.size()
                          << "\n";

    std::stringstream ss;
    for (vmi::Imports::const_iterator it = imports.begin(); it != imports.end(); ++it) {
        const std::string &libName = (*it).first;
        const vmi::ImportedSymbols &symbols = (*it).second;
        ss << libName << std::dec << " (" << symbols.size() << " symbols)\n";

        for (vmi::ImportedSymbols::const_iterator fit = symbols.begin(); fit != symbols.end(); ++fit) {
            std::string symbolName = (*fit).first;
            target_ulong itl = (*fit).second.importTableLocation;
            target_ulong address = (*fit).second.address;

            ss << std::setfill(' ') << std::setw(40) << std::left << symbolName << " @0x" << std::hex << address
               << " @0x" << std::hex << itl;

            // Look if there is an available hook
            LibraryHooks::const_iterator hit = m_registeredHooks.find(libName);
            if (hit != m_registeredHooks.end()) {
                const FunctionHooks &fh = (*hit).second;
                FunctionHooks::const_iterator rit = fh.find(symbolName);
                if (rit != fh.end()) {
                    target_ulong hookAddress = (*rit).second;
                    ss << " Hook available @" << std::hex << hookAddress;

                    // Perform the patching here
                    target_ulong originalAddress;
                    if (state->readPointer(itl, originalAddress)) {
                        if (originalAddress == address) {
                            if (!state->writePointer(itl, hookAddress)) {
                                getWarningsStream(state) << "could not write hook location\n";
                                ss << " Hook failed";
                            }
                        } else {
                            getWarningsStream(state) << "IAT address mismatch\n";
                            ss << " Hook failed";
                        }
                    } else {
                        getWarningsStream(state) << "could not read hook location\n";
                        ss << " Hook failed";
                    }
                }
            }
            ss << "\n";
        }
    }

    getDebugStream(state) << ss.str() << "\n";

    delete pe;
    delete guestImage;

    return true;
}

void GuestCodePatching::opcodePatchExistingModule(S2EExecutionState *state, uint64_t guestDataPtr,
                                                  const S2E_HOOK_PLUGIN_COMMAND &command) {
    S2E_HOOK_PLUGIN_COMMAND cmd = command;
    const ModuleDescriptor *module;

    cmd.PatchModule.Outcome = 0;

    std::string ModuleName;
    bool ret = true;

    ret &= state->mem()->readString(cmd.PatchModule.ModuleName, ModuleName);
    if (!ret) {
        getWarningsStream(state) << "could not read module and/or function name\n";
        goto err1;
    }

    module = m_detector->getModule(state, ModuleName);
    if (!module) {
        getWarningsStream(state) << "could not find a descriptor for module " << ModuleName << "\n";
        goto err1;
    }

    if (!patchImports(state, *module)) {
        getWarningsStream(state) << "could not patch imports in module " << ModuleName << "\n";
        goto err1;
    }

    cmd.PatchModule.Outcome = 1;

err1:

    if (!state->mem()->writeMemoryConcrete(guestDataPtr, &cmd, sizeof(cmd))) {
        getWarningsStream(state) << "GuestCodePatching::opcodePatchExistingModule "
                                 << "Could not write outcome\n";
    }
}

void GuestCodePatching::opcodeRegisterKernelFunction(S2EExecutionState *state, const S2E_HOOK_PLUGIN_COMMAND &command) {
    bool ret = true;
    std::string ModuleName, FunctionName;
    ret &= state->mem()->readString(command.KernelFunction.ModuleName, ModuleName);
    ret &= state->mem()->readString(command.KernelFunction.FunctionName, FunctionName);
    if (!ret) {
        getWarningsStream(state) << "could not read module and/or function name\n";
        return;
    }

    getDebugStream(state) << "Registering hook for " << ModuleName << "!" << FunctionName << " using function @"
                          << hexval(command.KernelFunction.Address) << "\n";

    m_registeredHooks[ModuleName][FunctionName] = command.KernelFunction.Address;
}

void GuestCodePatching::opcodeRegisterEntryPoint(S2EExecutionState *state, uint64_t guestDataPtr,
                                                 const S2E_HOOK_PLUGIN_COMMAND &command) {
    uint64_t address = command.EntryPoint.Address;
    if (!address) {
        if (!command.EntryPoint.Hook) {
            return;
        }

        if (command.EntryPoint.ExternalFunctionAddress) {
            return;
        }

        getDebugStream(state) << "setting DriverEntry hook " << hexval(command.EntryPoint.Hook) << "\n";

        DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
        plgState->setMainEntryPointHook(command.EntryPoint.Hook);
        return;
    }

    const ModuleDescriptor *module = m_detector->getModule(state, address);

    if (!module) {
        getDebugStream(state) << "opcodeRegisterEntryPoint could not get module for entry point " << hexval(address)
                              << "\n";
        return;
    }

    GuestCodePatchingState::EntryPoint ep;

    if (command.EntryPoint.ExternalFunctionAddress) {
        ep.Address = command.EntryPoint.ExternalFunctionAddress;
    } else {
        ep.Address = module->ToNativeBase(address);
    }

    ep.Handle = command.EntryPoint.Handle;
    ep.Hook = command.EntryPoint.Hook;

    if (!state->mem()->readString(command.EntryPoint.Name, ep.Name)) {
        std::stringstream ss;
        ss << "entrypoint_" << std::hex << ep.Address;
        ep.Name = ss.str();
    }

    getDebugStream(state) << "registering entry point " << ep.Name << "@" << hexval(ep.Address) << " in module "
                          << module->Name << " hook @" << hexval(ep.Hook) << " Handle @" << hexval(ep.Handle) << "\n";

    DECLARE_PLUGINSTATE(GuestCodePatchingState, state);

    if (command.EntryPoint.ExternalFunctionAddress) {
        plgState->registerEntryPoint(*module, ep, true);
    } else {
        plgState->registerEntryPoint(*module, ep);
    }
}

void GuestCodePatching::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                               uint64_t guestDataSize) {
    S2E_HOOK_PLUGIN_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_HOOK_PLUGIN_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case REGISTER_KERNEL_FUNCTION: {
            opcodeRegisterKernelFunction(state, command);
        } break;

        case HOOK_MODULE_IMPORTS: {
            opcodePatchExistingModule(state, guestDataPtr, command);
            /* Flush the TB cache to make sure everything is instrumented properly for coverage */
            getDebugStream(state) << "flushing TB cache\n";
            tb_flush(env);
            state->setPc(state->getPc() + OPCODE_SIZE);
            throw CpuExitException();
        } break;

        case REGISTER_ENTRY_POINT: {
            opcodeRegisterEntryPoint(state, guestDataPtr, command);
        } break;

        case DEREGISTER_ENTRY_POINT: {
            DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
            if (command.EntryPoint.Address) {
                plgState->deregisterEntryPoint(command.EntryPoint.Address);
            } else if (command.EntryPoint.Handle) {
                plgState->deregisterAllEntryPoints(command.EntryPoint.Handle);
            }
        } break;

        case REGISTER_RETURN_HOOK: {
            DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
            getDebugStream(state) << "registering return hook " << hexval(command.ReturnHook) << "\n";
            plgState->setEntryPointReturnHook(command.ReturnHook);
        } break;

        case REGISTER_DIRECT_KERNEL_HOOK: {
            DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
            getDebugStream(state) << "registering direct kernel hook @" << hexval(command.DirectHook.HookedFunctionPc)
                                  << " hook=" << hexval(command.DirectHook.HookPc) << "\n";
            plgState->setDirectKernelHook(command.DirectHook.HookedFunctionPc, command.DirectHook.HookPc);
            tb_flush(env);
            state->setPc(state->getPc() + OPCODE_SIZE);
            throw CpuExitException();
        } break;

        case DEREGISTER_DIRECT_KERNEL_HOOK: {
            DECLARE_PLUGINSTATE(GuestCodePatchingState, state);
            getDebugStream(state) << "deregistering direct kernel hook @" << hexval(command.DirectHook.HookedFunctionPc)
                                  << "\n";
            if (plgState->isDirectKernelHook(command.DirectHook.HookedFunctionPc)) {
                plgState->removeDirectKernelHook(command.DirectHook.HookedFunctionPc);
            } else {
                getDebugStream(state) << hexval(command.DirectHook.HookedFunctionPc) << " was not hooked\n";
            }
        } break;
    }
}

/*******************************************************/

bool GuestCodePatching::readMemoryCb(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->readMemoryConcrete(address, dest, size);
}

bool GuestCodePatching::writeMemoryCb(void *opaque, uint64_t address, const void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->writeMemoryConcrete(address, dest, size);
}

/*******************************************************/

GuestCodePatchingState::GuestCodePatchingState() {
    m_mainEntryPointHookAddress = 0;
    m_entryPointReturnHook = 0;
}

GuestCodePatchingState::~GuestCodePatchingState() {
}

GuestCodePatchingState *GuestCodePatchingState::clone() const {
    GuestCodePatchingState *ret = new GuestCodePatchingState(*this);
    return ret;
}

PluginState *GuestCodePatchingState::factory(Plugin *p, S2EExecutionState *state) {
    return new GuestCodePatchingState();
}

void GuestCodePatchingState::registerEntryPoint(const ModuleDescriptor &module, const EntryPoint &ep, bool external) {
    EntryPoints &entryPoints = external ? m_externalEntryPoints : m_entryPoints;

    EntryPoints::iterator it = entryPoints.find(module);
    if (it == entryPoints.end()) {
        ModuleEntryPoints eps;
        eps.insert(ep);
        entryPoints[module] = eps;
        return;
    } else {
        (*it).second.insert(ep);
    }
}

void GuestCodePatchingState::deregisterEntryPoint(const ModuleDescriptor &module) {
    m_entryPoints.erase(module);
    m_externalEntryPoints.erase(module);
}

void GuestCodePatchingState::deregisterEntryPoint(uint64_t address, bool external) {
    EntryPoint dummy;
    dummy.Address = address;

    EntryPoints &entryPoints = external ? m_externalEntryPoints : m_entryPoints;

    foreach2 (it, entryPoints.begin(), entryPoints.end()) { (*it).second.erase(dummy); }
}

void GuestCodePatchingState::deregisterAllEntryPoints(uint64_t handle, bool external) {
    EntryPoints &entryPoints = external ? m_externalEntryPoints : m_entryPoints;

    foreach2 (it, entryPoints.begin(), entryPoints.end()) {
        ModuleEntryPoints &eps = (*it).second;
        ModuleEntryPoints toErase;
        foreach2 (it2, eps.begin(), eps.end()) {
            const EntryPoint &ep = (*it2);
            if (ep.Handle == handle) {
                toErase.insert(ep);
            }
        }

        foreach2 (it2, toErase.begin(), toErase.end()) { eps.erase(*it2); }
    }
}

uint64_t GuestCodePatchingState::getHookAddress(const ModuleDescriptor &module, uint64_t original,
                                                bool external) const {
    if (!external) {
        if (original == module.EntryPoint) {
            return m_mainEntryPointHookAddress;
        }
    }

    const EntryPoints &entryPoints = external ? m_externalEntryPoints : m_entryPoints;

    EntryPoints::const_iterator it = entryPoints.find(module);
    if (it == entryPoints.end()) {
        return 0;
    }

    const ModuleEntryPoints &eps = (*it).second;
    EntryPoint ep;
    ep.Address = original;
    ModuleEntryPoints::const_iterator hit = eps.find(ep);
    if (hit == eps.end()) {
        return 0;
    }

    return (*hit).Hook;
}

} // namespace plugins
} // namespace s2e
