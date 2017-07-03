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
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <utility>

namespace s2e {
namespace plugins {

class OSMonitor;
struct S2E_WINMON2_UNMAP_SECTION;

class ModuleMap : public Plugin {
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

private:
    OSMonitor *m_monitor;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s);
    void onMonitorLoad(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ModuleMap_H
