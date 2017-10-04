///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_MODULE_DESCRIPTOR_

#define _LUA_MODULE_DESCRIPTOR_

#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaModuleDescriptor {
private:
    ModuleDescriptor m_desc;

public:
    static const char className[];
    static Lunar<LuaModuleDescriptor>::RegType methods[];

    LuaModuleDescriptor(lua_State *L) {
    }

    LuaModuleDescriptor(const ModuleDescriptor &desc) {
        m_desc = desc;
    }

    int getPid(lua_State *L);
    int getName(lua_State *L);
    int getNativeBase(lua_State *L);
    int getLoadBase(lua_State *L);
    int getSize(lua_State *L);
    int getEntryPoint(lua_State *L);
};
}
}

#endif
