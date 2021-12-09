///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Lua/Lua.h>
#include <s2e/Plugins/Lua/LuaModuleDescriptor.h>
#include <s2e/Plugins/Lua/LuaS2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <map>
#include <unordered_map>

#include "ModuleMap.h"
#include "RegionMap.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleMap, "Tracks loaded modules", "", "OSMonitor");

////////////////////
// ModuleMapState //
////////////////////

namespace {

class ModuleMapManager : public ProcessRegionMapManager<ModuleDescriptorConstPtr> {
    void dump(llvm::raw_ostream &os, uint64_t pid) const {
        RegionMapIteratorCb<ModuleDescriptorConstPtr> lambda = [&](uint64_t start, uint64_t end,
                                                                   ModuleDescriptorConstPtr value) -> bool {
            os << "pid=" << hexval(pid);
            os << " [" << hexval(start) << ", " << hexval(end) << "] ";
            os << value.get();
            os << "\n";

            return true;
        };

        iterate(pid, lambda);
    }

public:
    void dump(llvm::raw_ostream &os) const {
        os << "==========================================\n";
        os << "Dumping loaded sections\n";
        for (auto &pid : m_regions) {
            dump(os, pid.first);
        }
        os << "==========================================\n";
    }
};

///
/// Keeps track of loaded modules across states.
///
class ModuleMapState : public PluginState {
private:
    ModuleMapManager m_mgr;

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

    ModuleDescriptorConstPtr getModule(uint64_t pid, uint64_t pc) const {
        return m_mgr.lookup(pid, pc);
    }

    void onModuleLoad(const ModuleDescriptor &module) {
        auto ptr = std::make_shared<const ModuleDescriptor>(module);

        // TODO: warn if overlapping regions
        for (auto &section : module.Sections) {
            auto range = AddressRange(section.runtimeLoadBase, section.size);
            m_mgr.add(module.Pid, range.start, range.start + range.size, ptr);
        }
    }

    void onModuleUnload(const ModuleDescriptor &module) {
        for (auto &section : module.Sections) {
            auto range = AddressRange(section.runtimeLoadBase, section.size);
            m_mgr.remove(module.Pid, range.start, range.start + range.size);
        }
    }

    void onProcessUnload(uint64_t addressSpace, uint64_t pid, uint64_t returnCode) {
        m_mgr.remove(pid);
    }

    void dump(llvm::raw_ostream &os) const {
        m_mgr.dump(os);
    }
};

/////////////////////////////
// ModuleMap Lua Interface //
/////////////////////////////

class LuaModuleMap {
private:
    ModuleMap *m_map;

public:
    static const char className[];
    static Lunar<LuaModuleMap>::RegType methods[];

    LuaModuleMap(lua_State *L) : m_map(nullptr) {
    }

    LuaModuleMap(ModuleMap *plg) : m_map(plg) {
    }

    int getModule(lua_State *L) {
        void *data = luaL_checkudata(L, 1, "LuaS2EExecutionState");
        if (!data) {
            m_map->getWarningsStream() << "Incorrect lua invocation\n";
            return 0;
        }

        LuaS2EExecutionState **ls = reinterpret_cast<LuaS2EExecutionState **>(data);
        auto md = m_map->getModule((*ls)->getState());
        if (!md) {
            return 0;
        }

        LuaModuleDescriptor **c =
            static_cast<LuaModuleDescriptor **>(lua_newuserdata(L, sizeof(LuaModuleDescriptor *)));
        *c = new LuaModuleDescriptor(md);
        luaL_getmetatable(L, "LuaModuleDescriptor");
        lua_setmetatable(L, -2);
        return 1;
    }
};

const char LuaModuleMap::className[] = "LuaModuleMap";

Lunar<LuaModuleMap>::RegType LuaModuleMap::methods[] = {LUNAR_DECLARE_METHOD(LuaModuleMap, getModule), {0, 0}};

} // anonymous namespace

///////////////
// ModuleMap //
///////////////

void ModuleMap::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &ModuleMap::onMonitorLoad));
    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleMap::onModuleLoad));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleMap::onModuleUnload));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ModuleMap::onProcessUnload));

    lua_State *L = s2e()->getConfig()->getState();
    Lunar<LuaModuleMap>::Register(L);
}

int ModuleMap::getLuaPlugin(lua_State *L) {
    // lua will manage the LuaExpression** ptr
    LuaModuleMap **c = static_cast<LuaModuleMap **>(lua_newuserdata(L, sizeof(LuaModuleMap *)));
    *c = new LuaModuleMap(this); // we manage this
    luaL_getmetatable(L, "LuaModuleMap");
    lua_setmetatable(L, -2);
    return 1;
}

void ModuleMap::onMonitorLoad(S2EExecutionState *state) {
    auto winmon2 = dynamic_cast<WindowsMonitor *>(m_monitor);
    if (winmon2 && !winmon2->moduleUnloadSupported()) {
        getDebugStream() << "Guest OS does not support native module unload, using workaround\n";
        winmon2->onNtUnmapViewOfSection.connect(sigc::mem_fun(*this, &ModuleMap::onNtUnmapViewOfSection));
    }
}

void ModuleMap::onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &s) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (s.Status) {
        return;
    }

    auto module = plgState->getModule(s.Pid, s.BaseAddress);
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

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (!m_monitor->initialized()) {
        return nullptr;
    }

    auto pid = m_monitor->getPid(state);
    auto pc = state->regs()->getPc();
    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (!m_monitor->initialized()) {
        return nullptr;
    }

    auto pid = m_monitor->getPid(state);
    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

ModuleDescriptorConstPtr ModuleMap::getModule(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    if (!m_monitor->initialized()) {
        return nullptr;
    }

    pid = m_monitor->translatePid(pid, pc);
    return plgState->getModule(pid, pc);
}

void ModuleMap::dump(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ModuleMapState, state);
    plgState->dump(getDebugStream(state));
}

void ModuleMap::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_MODULE_MAP_COMMAND command;

    // TODO: factor these checks out from all plugins
    // TODO: handleOpcodeInvocation should really return error code
    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_MODULE_MAP_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
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

            if (!state->mem()->write(command.ModuleInfo.ModuleName, module->Name.c_str(), maxLen)) {
                getWarningsStream(state) << "could not write module name to memory\n";
                break;
            }

            // Init these last, guest will check them for 0 for errors
            command.ModuleInfo.NativeLoadBase = module->NativeBase;
            command.ModuleInfo.RuntimeLoadBase = module->LoadBase;
            command.ModuleInfo.Size = module->Size;

            if (!state->mem()->write(guestDataPtr, &command, guestDataSize)) {
                getWarningsStream(state) << "could not write module info to memory\n";
                break;
            }
        } break;

        default: {
            getWarningsStream(state) << "unknown command\n";
        } break;
    }
}

} // namespace plugins
} // namespace s2e
