///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ModuleMap_H
#define S2E_PLUGINS_ModuleMap_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <utility>

namespace s2e {
namespace plugins {

// NOTE: these types must be in sync with those in guest-tools:
// guest-tools/windows/libcommon/include/s2e/ModuleMap.h
// TODO: factor these out to remove all duplication
typedef enum S2E_MODULE_MAP_COMMANDS { GET_MODULE_INFO } S2E_MODULE_MAP_COMMANDS;

typedef struct S2E_MODULE_MAP_MODULE_INFO {
    // Specified by the guest.
    // The plugin determines which module is located at this address/pid.
    uint64_t Address;
    uint64_t Pid;

    // Pointer to storage for ASCIIZ name of the module.
    // The guest provides the pointer, the plugin sets the name.
    uint64_t ModuleName;

    // Size of the name in bytes
    uint64_t ModuleNameSize;

    uint64_t RuntimeLoadBase;
    uint64_t NativeLoadBase;
    uint64_t Size;
} S2E_MODULE_MAP_MODULE_INFO;

typedef struct S2E_MODULE_MAP_COMMAND {
    S2E_MODULE_MAP_COMMANDS Command;
    union {
        S2E_MODULE_MAP_MODULE_INFO ModuleInfo;
    };
} S2E_MODULE_MAP_COMMAND;

class OSMonitor;
struct S2E_WINMON2_UNMAP_SECTION;

class ModuleMap : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN

public:
    typedef std::pair<const ModuleDescriptor * /* Module */, std::string /* Exported symbol name */> Export;

    ModuleMap(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    ModuleDescriptorList getModulesByPid(S2EExecutionState *state, uint64_t pid);
    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t pc);
    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc);
    const ModuleDescriptor *getModule(S2EExecutionState *state, uint64_t pid, const std::string &name);

    void dump(S2EExecutionState *state);

    /// Cache a module export at the given address.
    void cacheExport(S2EExecutionState *state, uint64_t address, const Export &exp);

    ///
    /// \brief Get an export at the given runtime address.
    ///
    /// Returns a \c nullptr if no export at the given address exists in the cache.
    ///
    const Export *getExport(S2EExecutionState *state, uint64_t address);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    OSMonitor *m_monitor;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s);
    void onMonitorLoad(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ModuleMap_H
