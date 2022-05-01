///
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

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/labeled_graph.hpp>
#include <boost/graph/topological_sort.hpp>
#include <string>
#include <vector>

#include <s2e/CorePlugin.h>
#include <s2e/PluginManager.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

using namespace boost;
using namespace std;

namespace s2e {

PluginManager::~PluginManager() {
    destroy();
}

void PluginManager::destroy() {
    foreach2 (it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        delete *it;
    }
    m_activePluginsList.clear();

    if (m_pluginsFactory) {
        delete m_pluginsFactory;
        m_pluginsFactory = nullptr;
    }
}

bool PluginManager::initialize(S2E *_s2e, ConfigFile *cfg) {
    m_pluginsFactory = new PluginsFactory();

    m_corePlugin = static_cast<CorePlugin *>(m_pluginsFactory->createPlugin(_s2e, "CorePlugin"));
    assert(m_corePlugin);

    m_activePluginsList.push_back(m_corePlugin);
    m_activePluginsMap.insert(make_pair(m_corePlugin->getPluginInfo()->name, m_corePlugin));
    if (!m_corePlugin->getPluginInfo()->functionName.empty())
        m_activePluginsMap.insert(make_pair(m_corePlugin->getPluginInfo()->functionName, m_corePlugin));

    vector<string> pluginNames = cfg->getStringList("plugins");

    /* Check and load plugins */
    foreach2 (it, pluginNames.begin(), pluginNames.end()) {
        const string &pluginName = *it;
        const PluginInfo *pluginInfo = m_pluginsFactory->getPluginInfo(pluginName);
        if (!pluginInfo) {
            std::cerr << "ERROR: plugin '" << pluginName << "' does not exist in this S2E installation" << '\n';
            return false;
        } else if (getPlugin(pluginInfo->name)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name << "' was already loaded "
                      << "(is it enabled multiple times ?)" << '\n';
            return false;
        } else if (!pluginInfo->functionName.empty() && getPlugin(pluginInfo->functionName)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name << "' with function '" << pluginInfo->functionName
                      << "' can not be loaded because" << '\n'
                      << "    this function is already provided by '"
                      << getPlugin(pluginInfo->functionName)->getPluginInfo()->name << "' plugin" << '\n';
            return false;
        } else {
            Plugin *plugin = m_pluginsFactory->createPlugin(_s2e, pluginName);
            assert(plugin);

            m_activePluginsList.push_back(plugin);
            m_activePluginsMap.insert(make_pair(plugin->getPluginInfo()->name, plugin));
            if (!plugin->getPluginInfo()->functionName.empty())
                m_activePluginsMap.insert(make_pair(plugin->getPluginInfo()->functionName, plugin));
        }
    }

    /* Check dependencies */
    foreach2 (it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        Plugin *p = *it;
        foreach2 (it, p->getPluginInfo()->dependencies.begin(), p->getPluginInfo()->dependencies.end()) {
            const string &name = *it;
            if (!getPlugin(name)) {
                std::cerr << "ERROR: plugin '" << p->getPluginInfo()->name << "' depends on plugin '" << name
                          << "' which is not enabled in config" << '\n';
                return false;
            }
        }
    }

    /* Initialize plugins in topological order */
    typedef boost::labeled_graph<adjacency_list<vecS, vecS, directedS, PluginGraphData>, const PluginInfo *>
        PluginGraph;

    PluginGraph g;

    /* Add all the plugin as vertices to the graph */
    foreach2 (it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        const PluginInfo *info = (*it)->getPluginInfo();
        boost::add_vertex(info, g);
        g[info].info = info;
    }

    /* Add dependencies (edges) */
    foreach2 (it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        const PluginInfo *info = (*it)->getPluginInfo();

        foreach2 (dit, info->dependencies.begin(), info->dependencies.end()) {
            const PluginInfo *dependentPlugin = getPlugin(*dit)->getPluginInfo();
            boost::add_edge_by_label(dependentPlugin, info, g);
        }
    }

    /* topological sort */
    std::deque<PluginGraph::vertex_descriptor> topo_order;
    boost::topological_sort(g.graph(), std::front_inserter(topo_order));

    foreach2 (it, topo_order.begin(), topo_order.end()) {
        const PluginInfo *info = g.graph()[(*it)].info;
        Plugin *p = getPlugin(info->name);
        _s2e->getInfoStream() << "Initializing " << info->name << "\n";
        p->configureLogLevel();
        p->initialize();
    }

    return true;
}

Plugin *PluginManager::getPlugin(const std::string &name) const {
    ActivePluginsMap::const_iterator it = m_activePluginsMap.find(name);
    if (it != m_activePluginsMap.end()) {
        return const_cast<Plugin *>(it->second);
    } else {
        return nullptr;
    }
}

void PluginManager::refreshPlugins() {
    foreach2 (it, m_activePluginsList.begin(), m_activePluginsList.end()) {
        (*it)->refresh();
    }
}
} // namespace s2e
