///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_GuestCodePatching_H
#define S2E_PLUGINS_GuestCodePatching_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class WindowsInterceptor;

typedef struct _S2E_HOOK {
    uint64_t ModuleName;
    uint64_t FunctionName;
    uint64_t Address;
} S2E_HOOK;

typedef struct _S2E_DIRECT_HOOK {
    uint64_t HookedFunctionPc;
    uint64_t HookPc;
} S2E_DIRECT_HOOK;

typedef struct _S2E_HOOK_MODULE_IMPORTS {
    uint64_t ModuleName;
    uint32_t Outcome;
} S2E_HOOK_MODULE_IMPORTS;

typedef struct _S2E_HOOK_ENTRYPOINT {
    uint64_t Name;

    /**
     * The address of the entrypoint.
     * A null address means the module's main entry point.
     */
    uint64_t Address;

    /**
     * The address of the hook (if available) that
     * the plugin will invoke instead of the real
     * entry point
     */
    uint64_t Hook;

    /**
     * Group which this entry point belongs to.
     * Useful to be able to deregister all entry points at once.
     */
    uint64_t Handle;

    /**
     * Address of a function to hook that is external to the module.
     * When non-null, Address must be any function belonging to
     * the calling driver.
     */
    uint64_t ExternalFunctionAddress;
} S2E_HOOK_ENTRYPOINT;

typedef enum _S2E_HOOK_PLUGIN_COMMANDS {
    REGISTER_KERNEL_FUNCTION,
    HOOK_MODULE_IMPORTS,
    REGISTER_ENTRY_POINT,
    DEREGISTER_ENTRY_POINT,
    REGISTER_RETURN_HOOK,

    /**
     * Direct hooks will cause a simple jump to the
     * hook function. Unlike other types of hooks,
     * the address of the hooked function will not be
     * passed to the hook. It is up to determine
     * the address of the original function, if needed.
     */
    REGISTER_DIRECT_KERNEL_HOOK,
    DEREGISTER_DIRECT_KERNEL_HOOK
} S2E_HOOK_PLUGIN_COMMANDS;

typedef struct _S2E_HOOK_PLUGIN_COMMAND {
    S2E_HOOK_PLUGIN_COMMANDS Command;
    union {
        S2E_HOOK KernelFunction;
        S2E_HOOK_MODULE_IMPORTS PatchModule;
        S2E_HOOK_ENTRYPOINT EntryPoint;
        S2E_DIRECT_HOOK DirectHook;
        uint64_t ReturnHook;
    };
} S2E_HOOK_PLUGIN_COMMAND;

class GuestCodePatching : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    // XXX: should normally be per-state, but for now we assume
    // that the lfidriver is started on the first path and never unloaded.
    typedef std::map<std::string, target_ulong> FunctionHooks;
    typedef std::map<std::string, FunctionHooks> LibraryHooks;
    typedef std::set<std::string> StringSet;

    struct EntryPoint {
        std::string Name;
        uint64_t ModuleAddress;

        bool operator<(const EntryPoint &ep) const {
            return ModuleAddress < ep.ModuleAddress;
        }
    };

    /* These collect all module entry points which will then
     * be sent to the load balancer */
    typedef std::set<EntryPoint> ModuleEntryPoints;
    typedef std::map<std::string, ModuleEntryPoints> EntryPoints;

    GuestCodePatching(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void registerModuleToPatch(const std::string &module) {
        m_drivers.insert(module);
    }

private:
    WindowsMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    Vmi *m_vmi;

    bool m_allowSelfCalls;

    LibraryHooks m_registeredHooks;
    StringSet m_drivers;

    /* All discovered entry points during execution */
    EntryPoints m_entryPoints;

    void onTimer();

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                   TranslationBlock *tb, uint64_t pc, bool staticTarget, uint64_t targetPc);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc, bool direct, uint64_t hookAddress);
    void onExecuteCall(S2EExecutionState *state, uint64_t pc);
    void invokeHook(S2EExecutionState *state, uint64_t pc, uint64_t hookAddress, uint64_t returnAddress);

    static bool readMemoryCb(void *opaque, uint64_t address, void *dest, unsigned size);
    static bool writeMemoryCb(void *opaque, uint64_t address, const void *dest, unsigned size);

    bool patchImports(S2EExecutionState *state, const ModuleDescriptor &module);

    void opcodePatchExistingModule(S2EExecutionState *state, uint64_t guestDataPtr,
                                   const S2E_HOOK_PLUGIN_COMMAND &command);

    void opcodeRegisterEntryPoint(S2EExecutionState *state, uint64_t guestDataPtr,
                                  const S2E_HOOK_PLUGIN_COMMAND &command);

    void opcodeRegisterKernelFunction(S2EExecutionState *state, const S2E_HOOK_PLUGIN_COMMAND &command);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    QObject *getEntryPoints();
};

class GuestCodePatchingState : public PluginState {
public:
    struct EntryPoint {
        std::string Name;
        uint64_t Address;
        uint64_t Hook;
        uint64_t Handle;

        bool operator<(const EntryPoint &other) const {
            return Address < other.Address;
        }
    };

    typedef std::set<EntryPoint> ModuleEntryPoints;
    typedef std::map<ModuleDescriptor, ModuleEntryPoints, ModuleDescriptor::ModuleByLoadBase> EntryPoints;
    typedef std::set<std::string> StringSet;
    typedef llvm::DenseMap<uint64_t, uint64_t> DirectKernelHooks;

private:
    EntryPoints m_entryPoints;
    uint64_t m_mainEntryPointHookAddress;

    /* Used in 64-bits mode as the return address of entry point annotations */
    uint64_t m_entryPointReturnHook;

    /**
     * Hooks for function pointers located in data structures.
     * The addresses are absolute. The module indicates in what context
     * to hook the function.
     */
    EntryPoints m_externalEntryPoints;

    StringSet m_loadedModules;

    DirectKernelHooks m_directKernelHooks;

public:
    GuestCodePatchingState();
    virtual ~GuestCodePatchingState();
    virtual GuestCodePatchingState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void registerEntryPoint(const ModuleDescriptor &module, const EntryPoint &ep, bool external = false);
    void deregisterEntryPoint(const ModuleDescriptor &module);
    void deregisterEntryPoint(uint64_t address, bool external = false);
    void deregisterAllEntryPoints(uint64_t handle, bool external = false);

    uint64_t getHookAddress(const ModuleDescriptor &module, uint64_t original, bool external = false) const;
    void setMainEntryPointHook(uintptr_t hook) {
        m_mainEntryPointHookAddress = hook;
    }

    uint64_t getEntryPointReturnHook() const {
        return m_entryPointReturnHook;
    }

    void setEntryPointReturnHook(uint64_t hook) {
        m_entryPointReturnHook = hook;
    }

    bool isModuleLoaded(const ModuleDescriptor &module) const {
        return m_loadedModules.find(module.Name) != m_loadedModules.end();
    }

    void loadModule(const ModuleDescriptor &module) {
        m_loadedModules.insert(module.Name);
    }

    void unloadModule(const ModuleDescriptor &module) {
        m_loadedModules.erase(module.Name);
        deregisterEntryPoint(module);
    }

    void setDirectKernelHook(uint64_t pc, uint64_t hookPc) {
        m_directKernelHooks[pc] = hookPc;
    }

    void removeDirectKernelHook(uint64_t pc) {
        m_directKernelHooks.erase(pc);
    }

    bool isDirectKernelHook(uint64_t pc) const {
        return m_directKernelHooks.find(pc) != m_directKernelHooks.end();
    }

    uint64_t getDiectKernelHookAddress(uint64_t pc) const {
        DirectKernelHooks::const_iterator it = m_directKernelHooks.find(pc);
        return (*it).second;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_GuestCodePatching_H
