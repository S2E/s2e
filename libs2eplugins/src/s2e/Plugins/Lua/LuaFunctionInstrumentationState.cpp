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

#include <s2e/S2E.h>

#include "LuaFunctionInstrumentationState.h"

namespace s2e {
namespace plugins {

const char LuaFunctionInstrumentationState::className[] = "LuaFunctionInstrumentationState";

Lunar<LuaFunctionInstrumentationState>::RegType LuaFunctionInstrumentationState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaFunctionInstrumentationState, skipFunction),
    LUNAR_DECLARE_METHOD(LuaFunctionInstrumentationState, isChild),
    {0, 0}};

int LuaFunctionInstrumentationState::isChild(lua_State *L) {
    lua_pushboolean(L, m_child);
    return 1;
}

int LuaFunctionInstrumentationState::skipFunction(lua_State *L) {
    if (lua_gettop(L) < 1) {
        m_skip = true;
    } else {
        m_skip = lua_toboolean(L, 1);
    }
    g_s2e->getDebugStream() << "skipFunction " << m_skip << '\n';
    return 0;
}
} // namespace plugins
} // namespace s2e
