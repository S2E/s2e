///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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
    ModuleMap(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    ModuleDescriptorConstPtr getModule(S2EExecutionState *state);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pc);
    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc);

    void dump(S2EExecutionState *state);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    virtual int getLuaPlugin(lua_State *L);

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
