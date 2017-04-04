///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_BINDINGS_

#define _LUA_S2E_BINDINGS_

#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaS2E {
private:
public:
    static const char className[];
    static Lunar<LuaS2E>::RegType methods[];

    LuaS2E(lua_State *lua) {
    }

    /* Print a debug string */
    int debug(lua_State *L);

    /* Print a message */
    int message(lua_State *L);

    /* Print a warning */
    int warning(lua_State *L);

    /* Exit S2E */
    int exit(lua_State *L);
};
}
}

#endif
