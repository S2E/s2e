///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "ModuleMap.h"

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleMap, "Tracks loaded modules", "", "OSMonitor");

namespace {
class ModuleMapState : public PluginState {
public:
    struct pid_t {};
    struct pidname_t {};
    struct pagedir_t {};
    struct pidpc_t {};

    typedef boost::multi_index_container<
        ModuleDescriptor,
        boost::multi_index::indexed_by<
            /** Don't need it for now
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<pagedir_t>,
                BOOST_MULTI_INDEX_MEMBER(ModuleDescriptor, uint64_t, AddressSpace)
            >, */
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<pidname_t>,
                                                   boost::multi_index::identity<ModuleDescriptor>,
                                                   ModuleDescriptor::ModuleByPidName>,
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<pid_t>,
                                                   BOOST_MULTI_INDEX_MEMBER(ModuleDescriptor, uint64_t, Pid)>,
            boost::multi_index::ordered_unique<boost::multi_index::tag<pidpc_t>,
                                               boost::multi_index::identity<ModuleDescriptor>,
                                               ModuleDescriptor::ModuleByLoadBasePid>>>
        Map;

    typedef Map::index<pid_t>::type ModulesByPid;
    typedef Map::index<pidpc_t>::type ModulesByPidPc;
    typedef Map::index<pidname_t>::type ModulesByPidName;
    // typedef Map::index<pagedir_t>::type ModulesByAddressSpace;

private:
    Map m_modules;

public:
    ModuleMapState() {
    }
    virtual ~ModuleMapState() {
    }
    virtual ModuleMapState *clone() const {
        return new ModuleMapState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ModuleMapState();
    }

    ModuleDescriptorList getModulesByPid(uint64_t pid) {
        ModuleDescriptorList result;
        ModulesByPid &byPid = m_modules.get<pid_t>();

        std::pair<ModulesByPid::const_iterator, ModulesByPid::const_iterator> p = byPid.equal_range(pid);

        foreach2 (it, p.first, p.second) { result.push_back(&(*it)); }

        return result;
    }

    const ModuleDescriptor *getModule(uint64_t pid, uint64_t pc) {
        ModuleDescriptor md;
        md.Pid = pid;
        md.LoadBase = pc;
        md.Size = 1;

        ModulesByPidPc &byPidPc = m_modules.get<pidpc_t>();
        ModulesByPidPc::const_iterator it = byPidPc.find(md);
        if (it != byPidPc.end()) {
            return &*it;
        }

        return NULL;
    }

    const ModuleDescriptor *getModule(uint64_t pid, const std::string &name) {
        ModuleDescriptor md;
        md.Pid = pid;
        md.Name = name;

        ModulesByPidName &byPidName = m_modules.get<pidname_t>();
        ModulesByPidName::const_iterator it = byPidName.find(md);
        if (it != byPidName.end()) {
            return &*it;
        }

        return NULL;
    }

    void onModuleLoad(const ModuleDescriptor &module) {
        m_modules.insert(module);
    }

    void onModuleUnload(const ModuleDescriptor &module) {
        ModulesByPidPc &byPidPc = m_modules.get<pidpc_t>();
        ModulesByPidPc::const_iterator it = byPidPc.find(module);
        if (it == byPidPc.end()) {
            return;
        }

        assert((*it).Pid == module.Pid);
        if ((*it).LoadBase != module.LoadBase) {
            g_s2e->getDebugStream(g_s2e_state) << "ModuleMap::onModuleUnload mismatched base addresses:\n"
                                               << "  looked for:" << module << "\n"
                                               << "  found     :" << *it << "\n";
        }
        byPidPc.erase(it);
    }

    void onProcessUnload(uint64_t addressSpace, uint64_t pid) {
        ModulesByPid &byPid = m_modules.get<pid_t>();
        ModulesByPid::const_iterator it;
        while ((it = byPid.find(pid)) != byPid.end()) {
            byPid.erase(it);
        }
    }

    void dump(llvm::raw_ostream &os) const {
        os << "==========================================\n";
        os << "Dumping loaded modules\n";
        foreach2 (it, m_modules.begin(), m_modules.end()) { os << *it << "\n"; }
        os << "==========================================\n";
    }
};
}

void ModuleMap::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleMap::onModuleLoad));

    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleMap::onModuleUnload));

    WindowsMonitor *winmon2 = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (winmon2) {
        winmon2->onMonitorLoad.connect(sigc::mem_fun(*this, &ModuleMap::onMonitorLoad));
    }
}

void ModuleMap::onMonitorLoad(S2EExecutionState *state) {
    WindowsMonitor *winmon2 = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (!winmon2->moduleUnloadSupported()) {
        getDebugStream() << "Guest OS does not support native module unload, using workaround\n";
        winmon2->onNtUnmapViewOfSection.connect(sigc::mem_fun(*this, &ModuleMap::onNtUnmapViewOfSection));
    }
}

void ModuleMap::onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (s.Status) {
        return;
    }

    const ModuleDescriptor *module = plgState->getModule(s.Pid, s.BaseAddress);
    if (!module) {
        return;
    }

    getDebugStream(state) << "Unloading section " << hexval(s.BaseAddress) << " of module " << *module << "\n";
    plgState->onModuleUnload(*module);
}

void ModuleMap::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onModuleLoad(module);
}

void ModuleMap::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onModuleUnload(module);
}

void ModuleMap::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onProcessUnload(addressSpace, pid);
}

ModuleDescriptorList ModuleMap::getModulesByPid(S2EExecutionState *state, uint64_t pid) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModulesByPid(pid);
}

const ModuleDescriptor *ModuleMap::getModule(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModule(m_monitor->getPid(state, pc), pc);
}

const ModuleDescriptor *ModuleMap::getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModule(pid, pc);
}

const ModuleDescriptor *ModuleMap::getModule(S2EExecutionState *state, uint64_t pid, const std::string &name) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getModule(pid, name);
}

void ModuleMap::dump(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->dump(getDebugStream(state));
}

} // namespace plugins
} // namespace s2e
