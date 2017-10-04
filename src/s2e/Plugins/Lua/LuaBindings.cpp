///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include "LuaAnnotationState.h"
#include "LuaBindings.h"
#include "LuaExpression.h"
#include "LuaModuleDescriptor.h"
#include "LuaS2E.h"
#include "LuaS2EExecutionState.h"
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaBindings, "S2E interface for Lua annotations", "LuaBindings", );

void LuaBindings::initialize() {
    lua_State *L = s2e()->getConfig()->getState();
    Lunar<LuaModuleDescriptor>::Register(L);
    Lunar<LuaS2E>::Register(L);

    m_luaS2E = new LuaS2E(L);
    Lunar<LuaS2E>::push(L, m_luaS2E);
    lua_setglobal(L, "g_s2e");

    Lunar<LuaAnnotationState>::Register(L);
    Lunar<LuaS2EExecutionState>::Register(L);
    Lunar<LuaS2EExecutionStateMemory>::Register(L);
    Lunar<LuaS2EExecutionStateRegisters>::Register(L);
    Lunar<LuaExpression>::Register(L);
}

} // namespace plugins
} // namespace s2e
