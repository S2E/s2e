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

#ifndef __S2E_PLUGIN_STATE_MANAGER_H__

#define __S2E_PLUGIN_STATE_MANAGER_H__

#include <s2e/Plugin.h>

namespace s2e {

typedef std::unordered_map<const Plugin *, PluginState *> PluginStateMap;
typedef PluginState *(*PluginStateFactory)(Plugin *p);

class PluginStateManager {
private:
    PluginStateMap m_pluginState = {};
    PluginState *m_cachedPluginState = nullptr;
    const Plugin *m_cachedPlugin = nullptr;

public:
    PluginStateManager() = default;
    PluginStateManager(PluginStateManager &other) {
        m_pluginState = {};
        m_cachedPlugin = nullptr;
        m_cachedPluginState = nullptr;

        for (auto it : other.m_pluginState) {
            m_pluginState.insert(std::make_pair(it.first, it.second->clone()));
        }
    }

    ~PluginStateManager() {
        for (auto it : m_pluginState) {
            delete it.second;
        }
        m_pluginState.clear();
    }

    PluginState *getPluginState(Plugin *plugin, PluginStateFactory factory) {
        if (m_cachedPlugin == plugin) {
            return m_cachedPluginState;
        }

        PluginStateMap::iterator it = m_pluginState.find(plugin);
        if (it == m_pluginState.end()) {
            PluginState *ret = factory(plugin);
            assert(ret);
            m_pluginState[plugin] = ret;
            m_cachedPlugin = plugin;
            m_cachedPluginState = ret;
            return ret;
        }

        m_cachedPlugin = plugin;
        m_cachedPluginState = (*it).second;
        return (*it).second;
    }

    template <typename T> T *getPluginState(const Plugin *plugin) const {
        if (m_cachedPlugin == plugin) {
            return dynamic_cast<T *>(m_cachedPluginState);
        }

        auto it = m_pluginState.find(plugin);
        if (it == m_pluginState.end()) {
            return nullptr;
        }
        return dynamic_cast<T *>((*it).second);
    }
};

} // namespace s2e

#endif
