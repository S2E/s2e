///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_EXECUTION_STATE_REGISTERS_

#define _LUA_S2E_EXECUTION_STATE_REGISTERS_

#include <s2e/S2EExecutionState.h>
#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaS2EExecutionStateRegisters {
private:
    S2EExecutionState *m_state;

public:
    static const char className[];
    static Lunar<LuaS2EExecutionStateRegisters>::RegType methods[];

    LuaS2EExecutionStateRegisters(lua_State *L) : m_state(nullptr) {
    }

    LuaS2EExecutionStateRegisters(S2EExecutionState *state) : m_state(state) {
    }

    int read(lua_State *L);
    int write(lua_State *L);
    int getPc(lua_State *L);
};
}
}

#endif
