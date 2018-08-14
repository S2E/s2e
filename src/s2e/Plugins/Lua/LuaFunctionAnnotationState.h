///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_FUNCTION_ANNOTATION_STATE_

#define _LUA_S2E_FUNCTION_ANNOTATION_STATE_

#include "Lua.h"
#include "LuaAnnotationState.h"

namespace s2e {
namespace plugins {

class LuaFunctionAnnotationState : public LuaAnnotationState {
private:
    bool m_child;
    bool m_skip;

public:
    static const char className[];
    static Lunar<LuaFunctionAnnotationState>::RegType methods[];
    LuaFunctionAnnotationState(lua_State *L) : LuaAnnotationState(L) {
    }

    LuaFunctionAnnotationState() : LuaAnnotationState(), m_child(false), m_skip(false) {
    }

    void setChild(bool c) {
        m_child = c;
    }

    bool doSkip() const {
        return m_skip;
    }

    int skipFunction(lua_State *L);
    int isChild(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
