///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>

#include "LuaFunctionAnnotationState.h"

namespace s2e {
namespace plugins {

const char LuaFunctionAnnotationState::className[] = "LuaFunctionAnnotationState";

Lunar<LuaFunctionAnnotationState>::RegType LuaFunctionAnnotationState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaFunctionAnnotationState, skipFunction),
    LUNAR_DECLARE_METHOD(LuaFunctionAnnotationState, isChild),
    LUNAR_DECLARE_METHOD(LuaFunctionAnnotationState, setExitCpuLoop),
    {0, 0}};

int LuaFunctionAnnotationState::isChild(lua_State *L) {
    lua_pushboolean(L, m_child);
    return 1;
}

int LuaFunctionAnnotationState::skipFunction(lua_State *L) {
    if (lua_gettop(L) < 1) {
        m_skip = true;
    } else {
        m_skip = lua_toboolean(L, 1);
    }
    g_s2e->getDebugStream() << "skipFunction " << m_skip << '\n';
    return 0;
}
} // namespace plugins
} // namespace s2e
