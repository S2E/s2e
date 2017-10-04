///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/s2e_libcpu.h>

#include "LuaAnnotationState.h"

namespace s2e {
namespace plugins {

const char LuaAnnotationState::className[] = "LuaAnnotationState";

Lunar<LuaAnnotationState>::RegType LuaAnnotationState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaAnnotationState, setSkip),
    LUNAR_DECLARE_METHOD(LuaAnnotationState, isChild),
    LUNAR_DECLARE_METHOD(LuaAnnotationState, setExitCpuLoop),
    {0, 0}};

int LuaAnnotationState::setSkip(lua_State *L) {
    m_skip = lua_toboolean(L, 1);
    g_s2e->getDebugStream() << "setSkip " << m_skip << '\n';
    return 0;
}

int LuaAnnotationState::isChild(lua_State *L) {
    lua_pushboolean(L, m_child);
    return 1;
}

int LuaAnnotationState::setExitCpuLoop(lua_State *L) {
    g_s2e->getDebugStream() << "requested to exit cpu loop\n";
    m_exitCpuLoop = true;
    return 0;
}
}
}
