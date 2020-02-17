///
/// Copyright (C) 2014-2016, Cyberhaven
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

    S2EExecutionState *getState() const {
        return m_state;
    }

    int mem(lua_State *L);
    int regs(lua_State *L);
    int getPointerSize(lua_State *L);
    int createSymbolicValue(lua_State *L);
    int kill(lua_State *L);
    int setPluginProperty(lua_State *L);
    int getPluginProperty(lua_State *L);
    int debug(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
