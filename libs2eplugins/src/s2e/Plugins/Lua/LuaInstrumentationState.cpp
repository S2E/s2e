///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/s2e_libcpu.h>

#include "LuaInstrumentationState.h"

namespace s2e {
namespace plugins {

const char LuaInstrumentationState::className[] = "LuaInstrumentationState";

Lunar<LuaInstrumentationState>::RegType LuaInstrumentationState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaInstrumentationState, setExitCpuLoop), {0, 0}};

int LuaInstrumentationState::setExitCpuLoop(lua_State *L) {
    g_s2e->getDebugStream() << "requested to exit cpu loop\n";
    m_exitCpuLoop = true;
    return 0;
}
} // namespace plugins
} // namespace s2e
