///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/s2e_libcpu.h>

#include "LuaPlugin.h"
#include "LuaS2E.h"

namespace s2e {
namespace plugins {

const char LuaS2E::className[] = "LuaS2E";

// clang-format off
Lunar<LuaS2E>::RegType LuaS2E::methods[] = {
    LUNAR_DECLARE_METHOD(LuaS2E, debug),
    LUNAR_DECLARE_METHOD(LuaS2E, info),
    LUNAR_DECLARE_METHOD(LuaS2E, warning),
    LUNAR_DECLARE_METHOD(LuaS2E, exit),
    LUNAR_DECLARE_METHOD(LuaS2E, getPlugin),
    {0, 0}
};
// clang-format on

int LuaS2E::getPlugin(lua_State *L) {
    const char *str = lua_tostring(L, 1);
    auto plugin = g_s2e->getPlugin(str);
    if (!plugin) {
        g_s2e->getWarningsStream() << "LuaS2E: could not get plugin " << str << "\n";
        return 0;
    }

    ILuaPlugin *luaPlg = dynamic_cast<ILuaPlugin *>(plugin);
    if (!luaPlg) {
        g_s2e->getWarningsStream() << "LuaS2E: plugin " << str << " does not implement ILuaPlugin\n";
        return 0;
    }

    return luaPlg->getLuaPlugin(L);
}

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

    g_s2e->getInfoStream(g_s2e_state) << "Lua instrumentation requested S2E exit\n";

    ::exit(returnCode);
    return 0;
}
} // namespace plugins
} // namespace s2e
