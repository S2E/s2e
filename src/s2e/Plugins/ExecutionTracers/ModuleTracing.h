///
/// Copyright (C) 2020, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_IMODTRACE_H

#define S2E_PLUGINS_IMODTRACE_H

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <unordered_set>

namespace s2e {
namespace plugins {

///
/// \brief This is a helper class that can be used by plugins
/// that need to trace specific modules.
///
class ModuleTracing {
private:
    ModuleMap *m_modules;
    std::unordered_set<std::string> m_enabledModules;

public:
    void initialize(S2E *s2e, const std::string &cfgKey) {
        m_modules = s2e->getPlugin<ModuleMap>();
        auto modules = s2e->getConfig()->getStringList(cfgKey + ".moduleNames");
        m_enabledModules.insert(modules.begin(), modules.end());
    }

    bool isModuleTraced(S2EExecutionState *state, uint64_t pc) {
        // If no modules are specified, trace the entire process
        bool tracedModule = true;
        if (m_enabledModules.size()) {
            auto mod = m_modules->getModule(state, pc);
            if (mod) {
                tracedModule = m_enabledModules.find(mod->Name) != m_enabledModules.end();
            } else {
                tracedModule = false;
            }
        }

        return tracedModule;
    }
};
}
}

#endif
