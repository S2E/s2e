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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include "LuaBindings.h"
#include "LuaExpression.h"
#include "LuaFunctionInstrumentationState.h"
#include "LuaInstructionInstrumentationState.h"
#include "LuaInstrumentationState.h"
#include "LuaModuleDescriptor.h"
#include "LuaS2E.h"
#include "LuaS2EExecutionState.h"
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaBindings, "S2E interface for Lua instrumentation", "LuaBindings", );

void LuaBindings::initialize() {
    lua_State *L = s2e()->getConfig()->getState();
    Lunar<LuaModuleDescriptor>::Register(L);
    Lunar<LuaS2E>::Register(L);

    m_luaS2E = new LuaS2E(L);
    Lunar<LuaS2E>::push(L, m_luaS2E);
    lua_setglobal(L, "g_s2e");

    Lunar<LuaInstrumentationState>::Register(L);
    Lunar<LuaFunctionInstrumentationState>::Register(L);
    Lunar<LuaInstructionInstrumentationState>::Register(L);
    Lunar<LuaS2EExecutionState>::Register(L);
    Lunar<LuaS2EExecutionStateMemory>::Register(L);
    Lunar<LuaS2EExecutionStateRegisters>::Register(L);
    Lunar<LuaExpression>::Register(L);
}

} // namespace plugins
} // namespace s2e
