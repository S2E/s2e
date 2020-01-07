///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>

#include "LuaInstructionInstrumentationState.h"

namespace s2e {
namespace plugins {

const char LuaInstructionInstrumentationState::className[] = "LuaInstructionInstrumentationState";

Lunar<LuaInstructionInstrumentationState>::RegType LuaInstructionInstrumentationState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaInstructionInstrumentationState, skipInstruction),
    LUNAR_DECLARE_METHOD(LuaInstructionInstrumentationState, setExitCpuLoop),
    {0, 0}};

int LuaInstructionInstrumentationState::skipInstruction(lua_State *L) {
    if (lua_gettop(L) < 1) {
        m_skip = true;
    } else {
        m_skip = lua_toboolean(L, 1);
    }
    g_s2e->getDebugStream() << "skipInstruction " << m_skip << '\n';
    return 0;
}
} // namespace plugins
} // namespace s2e
