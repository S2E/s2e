///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_EXPRESSION_

#define _LUA_S2E_EXPRESSION_

#include <s2e/S2EExecutionState.h>
#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaExpression {
private:
    klee::ref<klee::Expr> m_expr;

public:
    static const char className[];
    static Lunar<LuaExpression>::RegType methods[];

    LuaExpression(lua_State *lua) : m_expr(NULL) {
    }

    LuaExpression(klee::ref<klee::Expr> &expr) : m_expr(expr) {
    }

    klee::ref<klee::Expr> get() const {
        return m_expr;
    }
};
}
}

#endif
