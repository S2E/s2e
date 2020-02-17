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
