///
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
};

} // namespace plugins
} // namespace s2e

#endif
