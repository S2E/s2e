///
/// Copyright (C) 2015-2016, Cyberhaven
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

#ifndef __S2E_PLUGIN_MANAGER_H__

#define __S2E_PLUGIN_MANAGER_H__

#include <s2e/ConfigFile.h>
#include <s2e/Plugin.h>

#include <unordered_map>

namespace s2e {
class CorePlugin;
class S2E;

class PluginManager {
private:
    PluginsFactory *m_pluginsFactory;

    CorePlugin *m_corePlugin;
    std::vector<Plugin *> m_activePluginsList;

    typedef std::unordered_map<std::string, Plugin *> ActivePluginsMap;
    ActivePluginsMap m_activePluginsMap;

public:
    PluginManager() : m_pluginsFactory(nullptr), m_corePlugin(nullptr) {
    }

    ~PluginManager();

    bool initialize(S2E *_s2e, ConfigFile *cfg);

    CorePlugin *getCorePlugin() const {
        return m_corePlugin;
    }

    Plugin *getPlugin(const std::string &name) const;
    template <class PluginClass> PluginClass *getPlugin() const;

    void refreshPlugins();
    void destroy();
};

template <class PluginClass> PluginClass *PluginManager::getPlugin() const {
    return static_cast<PluginClass *>(getPlugin(PluginClass::getPluginInfoStatic()->name));
}
} // namespace s2e

#endif
