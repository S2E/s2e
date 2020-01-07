///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_PLUGIN_INTERFACE_
#define _LUA_S2E_PLUGIN_INTERFACE_

#include "Lua.h"

namespace s2e {
namespace plugins {

class ILuaPlugin {
public:
    virtual int getLuaPlugin(lua_State *L) = 0;
};

} // namespace plugins
} // namespace s2e

#endif
