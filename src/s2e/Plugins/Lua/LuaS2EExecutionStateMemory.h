///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_EXECUTION_STATE_MEMORY_
#define _LUA_S2E_EXECUTION_STATE_MEMORY_

#include "Lua.h"

namespace s2e {

class S2EExecutionState;

namespace plugins {

class LuaS2EExecutionStateMemory {
private:
    S2EExecutionState *m_state;

public:
    static const char className[];
    static Lunar<LuaS2EExecutionStateMemory>::RegType methods[];

    LuaS2EExecutionStateMemory(lua_State *L) : m_state(nullptr) {
    }

    LuaS2EExecutionStateMemory(S2EExecutionState *state) : m_state(state) {
    }

    int readPointer(lua_State *L);
    int readBytes(lua_State *L);
    int write(lua_State *L);

    int makeSymbolic(lua_State *L);
    int makeConcolic(lua_State *L);
};

} // namespace plugins
} // namespace s2e

#endif
