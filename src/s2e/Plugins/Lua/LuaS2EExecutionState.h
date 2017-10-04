///
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_EXECUTION_STATE_

#define _LUA_S2E_EXECUTION_STATE_

#include <s2e/S2EExecutionState.h>
#include "Lua.h"
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"

namespace s2e {
namespace plugins {

class LuaS2EExecutionState {
private:
    S2EExecutionState *m_state;
    LuaS2EExecutionStateMemory m_memory;
    LuaS2EExecutionStateRegisters m_registers;

public:
    static const char className[];
    static Lunar<LuaS2EExecutionState>::RegType methods[];

    LuaS2EExecutionState(lua_State *L)
        : m_state(nullptr), m_memory((S2EExecutionState *) nullptr), m_registers((S2EExecutionState *) nullptr) {
    }

    LuaS2EExecutionState(S2EExecutionState *state) : m_state(state), m_memory(state), m_registers(state) {
    }

    int mem(lua_State *L);
    int regs(lua_State *L);
    int createSymbolicValue(lua_State *L);
    int kill(lua_State *L);
    int setPluginProperty(lua_State *L);
    int getPluginProperty(lua_State *L);
    int debug(lua_State *L);
};
}
}

#endif
