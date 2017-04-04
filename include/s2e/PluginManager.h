///
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

/**
 * Copyright 2015 - CodeTickler
 * Proprietary and confidential
 */

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
    PluginManager() : m_pluginsFactory(NULL), m_corePlugin(NULL) {
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
}

#endif
