///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/s2e_libcpu.h>

#include "LuaS2E.h"

namespace s2e {
namespace plugins {

const char LuaS2E::className[] = "LuaS2E";

Lunar<LuaS2E>::RegType LuaS2E::methods[] = {LUNAR_DECLARE_METHOD(LuaS2E, debug),
                                            LUNAR_DECLARE_METHOD(LuaS2E, info),
                                            LUNAR_DECLARE_METHOD(LuaS2E, warning),
                                            LUNAR_DECLARE_METHOD(LuaS2E, exit),
                                            {0, 0}};

int LuaS2E::debug(lua_State *L) {
    const char *str = lua_tostring(L, 1);
    g_s2e->getDebugStream(g_s2e_state) << str << "\n";
    return 0;
}

int LuaS2E::info(lua_State *L) {
    const char *str = lua_tostring(L, 1);
    g_s2e->getInfoStream(g_s2e_state) << str << "\n";
    return 0;
}

int LuaS2E::warning(lua_State *L) {
    const char *str = lua_tostring(L, 1);
    g_s2e->getWarningsStream(g_s2e_state) << str << "\n";
    return 0;
}

int LuaS2E::exit(lua_State *L) {
    long returnCode = (long) luaL_checkinteger(L, 1);

    g_s2e->getInfoStream(g_s2e_state) << "Lua annotation requested S2E exit\n";

    ::exit(returnCode);
    return 0;
}
}
}
