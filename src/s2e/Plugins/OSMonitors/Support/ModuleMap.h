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
#include <s2e/Plugins/Lua/LuaPlugin.h>
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

class ModuleMap : public Plugin, public IPluginInvoker, public ILuaPlugin {
    S2E_PLUGIN

public:
    typedef std::pair<ModuleDescriptorConstPtr /* Module */, std::string /* Exported symbol name */> Export;

    ModuleMap(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    ModuleDescriptorList getModulesByPid(S2EExecutionState *state, uint64_t pid);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pc);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pid, const std::string &name);

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

    virtual int getLuaPlugin(lua_State *L);

private:
    OSMonitor *m_monitor;
    uint64_t m_cachedKernelStart;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s);
    void onMonitorLoad(S2EExecutionState *state);

    ///
    /// \brief translatePid
    ///
    /// Windows and Linux OSes typically split the address space in two: kernel and user.
    /// The kernel is shared between all address spaces and processes. Therefore, any module
    /// loaded in kernel space is "visible" to all processes. By convention, S2E plugins
    /// assign a pid 0 to such modules. When a plugin wants to get a module loaded at a given
    /// (pid, pc), we need to set the pid to 0 if pc falls in the kernel area. It is the
    /// responsibility of the OS monitor plugins to set the pid to 0 when they emit an
    /// onModuleLoad signal for a module that is loaded in kernel space.
    ///
    /// \param pid the original process id
    /// \param pc the program counter to query
    /// \return 0 if pc is in kernel space, pid otherwise
    ///
    uint64_t translatePid(uint64_t pid, uint64_t pc) const {
        if (pc >= m_cachedKernelStart) {
            return 0;
        } else {
            return pid;
        }
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ModuleMap_H
