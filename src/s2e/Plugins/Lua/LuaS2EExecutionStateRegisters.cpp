///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "LuaS2EExecutionStateRegisters.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include "LuaExpression.h"

namespace s2e {
namespace plugins {

const char LuaS2EExecutionStateRegisters::className[] = "LuaS2EExecutionStateRegisters";

Lunar<LuaS2EExecutionStateRegisters>::RegType LuaS2EExecutionStateRegisters::methods[] = {
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateRegisters, getPc),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateRegisters, getSp),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateRegisters, write),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionStateRegisters, read),
    {0, 0}};

int LuaS2EExecutionStateRegisters::getPc(lua_State *L) {
    lua_pushinteger(L, m_state->regs()->getPc());
    return 1;
}

int LuaS2EExecutionStateRegisters::getSp(lua_State *L) {
    lua_pushinteger(L, m_state->regs()->getSp());
    return 1;
}

int LuaS2EExecutionStateRegisters::read(lua_State *L) {
    long offset = (long) luaL_checkinteger(L, 1);
    long size = (long) luaL_checkinteger(L, 2);
    RegReadFlags flags = CONCRETE;

    if (lua_gettop(L) == 3) {
        flags = (RegReadFlags) luaL_checkinteger(L, 3);
    }

    uint64_t value = 0;

    switch (flags) {
        case CONCRETE:
            switch (size) {
                case 1:
                    value = m_state->regs()->read<uint8_t>(offset);
                    break;
                case 2:
                    value = m_state->regs()->read<uint16_t>(offset);
                    break;
                case 4:
                    value = m_state->regs()->read<uint32_t>(offset);
                    break;
                case 8:
                    value = m_state->regs()->read<uint64_t>(offset);
                    break;
                default: {
                    std::stringstream ss;
                    ss << "LuaS2EExecutionStateRegisters::read: Incorrect size " << size << "\n";
                    g_s2e->getExecutor()->terminateState(*m_state, ss.str());
                    break;
                }
            }
            break;

        case CONCRETE_EXAMPLE: {
            auto expr = m_state->regs()->read(offset, size * 8);
            value = m_state->concretize(expr, "", true);
        } break;

        default: {
            std::stringstream ss;
            ss << "LuaS2EExecutionStateRegisters::read: Incorrect flags " << flags << "\n";
            g_s2e->getExecutor()->terminateState(*m_state, ss.str());
        }
    }

    lua_pushinteger(L, value);

    return 1;
}

int LuaS2EExecutionStateRegisters::write(lua_State *L) {
    long pointer = (long) luaL_checkinteger(L, 1);

    if (lua_isuserdata(L, 2)) {
        void *expr = luaL_checkudata(L, 2, "LuaExpression");
        LuaExpression *value = *static_cast<LuaExpression **>(expr);
        g_s2e->getDebugStream(m_state) << "Writing " << value->get() << "\n";
        m_state->regs()->write(pointer, value->get());
    } else if (lua_isnumber(L, 2)) {
        long value = (long) luaL_checkinteger(L, 2);
        long size = (long) luaL_checkinteger(L, 3);
        switch (size) {
            case 1:
                m_state->regs()->write<uint8_t>(pointer, value);
                break;
            case 2:
                m_state->regs()->write<uint16_t>(pointer, value);
                break;
            case 4:
                m_state->regs()->write<uint32_t>(pointer, value);
                break;
            case 8:
                m_state->regs()->write<uint64_t>(pointer, value);
                break;
            default:
                g_s2e->getDebugStream(m_state) << "LuaS2EExecutionStateRegisters::write: Incorrect size " << size
                                               << "\n";
                break;
        }
    }
    return 0;
}
}
}
