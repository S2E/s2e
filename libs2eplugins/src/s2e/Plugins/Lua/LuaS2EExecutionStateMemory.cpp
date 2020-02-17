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

#include <vector>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include "LuaExpression.h"
#include "LuaS2EExecutionStateMemory.h"

namespace s2e {
namespace plugins {

const char LuaS2EExecutionStateMemory::className[] = "LuaS2EExecutionStateMemory";

Lunar<LuaS2EExecutionStateMemory>::RegType LuaS2EExecutionStateMemory::methods[] = {
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, readPointer),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, readBytes),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, write),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, makeSymbolic),
    {0, 0}};

int LuaS2EExecutionStateMemory::readPointer(lua_State *L) {
    long address = (long) luaL_checkinteger(L, 1);

    uint64_t pointerSize = m_state->getPointerSize();
    if (pointerSize == 4) {
        uint32_t data = 0;
        if (!m_state->mem()->read(address, &data, sizeof(data))) {
            g_s2e->getWarningsStream(m_state) << "Could not read address " << hexval(address) << "\n";
            return 0;
        }
        lua_pushinteger(L, data);
    } else {
        uint64_t data = 0;
        if (!m_state->mem()->read(address, &data, sizeof(data))) {
            g_s2e->getWarningsStream(m_state) << "Could not read address " << hexval(address) << "\n";
            return 0;
        }
        lua_pushinteger(L, data);
    }

    return 1;
}

int LuaS2EExecutionStateMemory::readBytes(lua_State *L) {
    long address = (long) luaL_checkinteger(L, 1);
    long size = (long) luaL_checkinteger(L, 2);
    std::vector<uint8_t> bytes(size);

    if (!m_state->mem()->read(address, bytes.data(), size * sizeof(uint8_t))) {
        return 0;
    }

    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    luaL_addlstring(&buff, (char *) bytes.data(), size * sizeof(uint8_t));
    luaL_pushresult(&buff);

    return 1;
}

int LuaS2EExecutionStateMemory::write(lua_State *L) {
    long address = (long) luaL_checkinteger(L, 1);

    if (lua_isuserdata(L, 2)) {
        void *expr = luaL_checkudata(L, 2, "LuaExpression");
        LuaExpression *value = *static_cast<LuaExpression **>(expr);
        g_s2e->getDebugStream(m_state) << "Writing " << value->get() << "\n";
        m_state->mem()->write(address, value->get());
    } else if (lua_isnumber(L, 2)) {
        long value = (long) luaL_checkinteger(L, 2);
        long size = (long) luaL_checkinteger(L, 3);
        g_s2e->getDebugStream(m_state) << "Writing " << value << " of size " << size << "\n";
        switch (size) {
            case 1:
                m_state->mem()->write<uint8_t>(address, value);
                break;
            case 2:
                m_state->mem()->write<uint16_t>(address, value);
                break;
            case 4:
                m_state->mem()->write<uint32_t>(address, value);
                break;
            case 8:
                m_state->mem()->write<uint64_t>(address, value);
                break;
            default:
                g_s2e->getDebugStream(m_state)
                    << "LuaS2EExecutionStateRegisters::write: Incorrect size " << size << "\n";
                break;
        }
    }

    return 1;
}

int LuaS2EExecutionStateMemory::makeSymbolic(lua_State *L) {
    long address = (long) luaL_checkinteger(L, 1);
    long size = (long) luaL_checkinteger(L, 2);
    std::string name = luaL_checkstring(L, 3);

    std::vector<uint8_t> concreteData(size);
    if (!m_state->mem()->read(address, concreteData.data(), size * sizeof(uint8_t))) {
        lua_pushinteger(L, 0);
        return 1;
    }

    std::vector<klee::ref<klee::Expr>> symb = m_state->createSymbolicArray(name, size, concreteData);

    for (unsigned i = 0; i < size; ++i) {
        if (!m_state->mem()->write(address + i, symb[i])) {
            lua_pushinteger(L, 0);
            return 1;
        }
    }

    lua_pushinteger(L, 1);
    return 1;
}

} // namespace plugins
} // namespace s2e
