///
/// Copyright (C) 2020, Cyberhaven
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
} // namespace plugins
} // namespace s2e

#endif
