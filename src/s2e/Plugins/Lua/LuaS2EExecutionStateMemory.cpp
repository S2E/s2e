///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "LuaS2EExecutionStateMemory.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include "LuaExpression.h"

namespace s2e {
namespace plugins {

const char LuaS2EExecutionStateMemory::className[] = "LuaS2EExecutionStateMemory";

Lunar<LuaS2EExecutionStateMemory>::RegType LuaS2EExecutionStateMemory::methods[] = {
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, readPointer),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateMemory, write),
    {0, 0}};

int LuaS2EExecutionStateMemory::readPointer(lua_State *L) {
    uint64_t value = luaL_checklong(L, 1);

    uint64_t pointerSize = m_state->getPointerSize();
    if (pointerSize == 4) {
        uint32_t data = 0;
        m_state->mem()->readMemoryConcrete(value, &data, sizeof(data));
        lua_pushinteger(L, data);
    } else {
        uint64_t data = 0;
        m_state->mem()->readMemoryConcrete(value, &data, sizeof(data));
        lua_pushinteger(L, data);
    }

    return 1;
}

int LuaS2EExecutionStateMemory::write(lua_State *L) {
    uint64_t pointer = luaL_checklong(L, 1);
    void *expr = luaL_checkudata(L, 2, "LuaExpression");

    LuaExpression *value = *static_cast<LuaExpression **>(expr);
    g_s2e->getDebugStream(m_state) << "Writing " << value->get() << " to " << hexval(pointer) << "\n";
    m_state->mem()->writeMemory(pointer, value->get());
    return 0;
}
}
}
