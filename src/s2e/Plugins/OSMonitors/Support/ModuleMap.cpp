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

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <list>
#include <unordered_map>

#include "ModuleMap.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleMap, "Tracks loaded modules", "", "OSMonitor");

////////////////////
// ModuleMapState //
////////////////////

namespace {

///
/// Keeps track of loaded modules across states.
///
/// The \c ModuleMapState can also act as a LRU cache for loaded modules' exports. The LRU cache code is adapted from
/// https://github.com/lamerman/cpp-lru-cache
///
class ModuleMapState : public PluginState {
public:
    struct pid_t {};
    struct pidname_t {};
    struct pagedir_t {};
    struct pidpc_t {};

    typedef boost::multi_index_container<
        ModuleDescriptor,
        boost::multi_index::indexed_by<
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

private:
    // Module-related members
    Map m_modules;

    // Export-related members
    typedef std::pair<uint64_t, ModuleMap::Export> AddressExportPair;
    typedef std::list<AddressExportPair>::iterator AddressExportIterator;

    std::list<AddressExportPair> m_exportCacheList;
    std::unordered_map<uint64_t, AddressExportIterator> m_exportCacheMap;

    const static size_t MAX_EXPORT_CACHE_SIZE = 50;

public:
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

        return nullptr;
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

        return nullptr;
    }

    void onModuleLoad(const ModuleDescriptor &module) {
        m_modules.insert(module);
    }

    void onModuleUnload(const ModuleDescriptor &module) {
        // Remove the module from the map
        ModulesByPidPc &byPidPc = m_modules.get<pidpc_t>();
        ModulesByPidPc::const_iterator it = byPidPc.find(module);
        if (it != byPidPc.end()) {
            assert(it->Pid == module.Pid);
            if (it->LoadBase != module.LoadBase) {
                g_s2e->getDebugStream(g_s2e_state) << "ModuleMap::onModuleUnload mismatched base addresses:\n"
                                                   << "  looked for:" << module << "\n"
                                                   << "  found     :" << *it << "\n";
            }

            byPidPc.erase(it);
        }

        // When a module is unloaded, we need to invalidate all entries in the cache that correspond to the unloaded
        // module's address space
        for (auto it = m_exportCacheMap.begin(); it != m_exportCacheMap.end();) {
            if (module.Contains(it->first)) {
                m_exportCacheList.erase(it->second);
                it = m_exportCacheMap.erase(it);
            } else {
                ++it;
            }
        }
    }

    void onProcessUnload(uint64_t addressSpace, uint64_t pid, uint64_t returnCode) {
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

    void cacheExport(uint64_t address, const ModuleMap::Export &exp) {
        auto it = m_exportCacheMap.find(address);
        m_exportCacheList.push_front({address, exp});

        if (it != m_exportCacheMap.end()) {
            m_exportCacheList.erase(it->second);
            m_exportCacheMap.erase(it);
        }

        m_exportCacheMap[address] = m_exportCacheList.begin();

        if (m_exportCacheMap.size() > MAX_EXPORT_CACHE_SIZE) {
            auto last = m_exportCacheList.end();
            last--;
            m_exportCacheMap.erase(last->first);
            m_exportCacheList.pop_back();
        }
    }

    const ModuleMap::Export *getExport(uint64_t address) {
        auto it = m_exportCacheMap.find(address);
        if (it == m_exportCacheMap.end()) {
            return nullptr;
        } else {
            m_exportCacheList.splice(m_exportCacheList.begin(), m_exportCacheList, it->second);
            return &(it->second->second);
        }
    }
};
} // anonymous namespace

///////////////
// ModuleMap //
///////////////

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

void ModuleMap::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->onProcessUnload(addressSpace, pid, returnCode);
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

void ModuleMap::cacheExport(S2EExecutionState *state, uint64_t address, const Export &exp) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->cacheExport(address, exp);
}

const ModuleMap::Export *ModuleMap::getExport(S2EExecutionState *state, uint64_t address) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    return plgState->getExport(address);
}

void ModuleMap::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_MODULE_MAP_COMMAND command;

    // TODO: factor these checks out from all plugins
    // TODO: handleOpcodeInvocation should really return error code
    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_MODULE_MAP_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case GET_MODULE_INFO: {
            DECLARE_PLUGINSTATE(ModuleMapState, state);
            auto module = plgState->getModule(command.ModuleInfo.Pid, command.ModuleInfo.Address);
            if (!module) {
                getWarningsStream(state) << "Could not get module for pid=" << hexval(command.ModuleInfo.Pid)
                                         << " addr=" << hexval(command.ModuleInfo.Address) << "\n";
                break;
            }

            // Caller inits the buffer to 0, so subtract 1 to make it asciiz
            auto maxLen = std::min(command.ModuleInfo.ModuleNameSize - 1, module->Name.size());

            if (!state->mem()->writeMemoryConcrete(command.ModuleInfo.ModuleName, module->Name.c_str(), maxLen)) {
                getWarningsStream(state) << "could not write module name to memory\n";
                break;
            }

            // Init these last, guest will check them for 0 for errors
            command.ModuleInfo.NativeLoadBase = module->NativeBase;
            command.ModuleInfo.RuntimeLoadBase = module->LoadBase;
            command.ModuleInfo.Size = module->Size;

            if (!state->mem()->writeMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
                getWarningsStream(state) << "could not write module info to memory\n";
                break;
            }
        } break;

        default: { getWarningsStream(state) << "unknown command\n"; } break;
    }
}

} // namespace plugins
} // namespace s2e
