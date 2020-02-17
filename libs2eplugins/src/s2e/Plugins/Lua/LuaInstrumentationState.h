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

#ifndef _LUA_S2E_ANNOTATION_STATE_

#define _LUA_S2E_ANNOTATION_STATE_

#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaInstrumentationState {
private:
    bool m_exitCpuLoop;

public:
    static const char className[];
    static Lunar<LuaInstrumentationState>::RegType methods[];

    LuaInstrumentationState(lua_State *L) : LuaInstrumentationState() {
    }

    LuaInstrumentationState() : m_exitCpuLoop(false) {
    }

    bool exitCpuLoop() const {
        return m_exitCpuLoop;
    }

    int setExitCpuLoop(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
