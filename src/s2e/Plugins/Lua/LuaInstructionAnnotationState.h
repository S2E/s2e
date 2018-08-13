///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _LUA_S2E_INSTRUCTION_ANNOTATION_STATE_

#define _LUA_S2E_INSTRUCTION_ANNOTATION_STATE_

#include "Lua.h"
#include "LuaAnnotationState.h"

namespace s2e {
namespace plugins {

class LuaInstructionAnnotationState : public LuaAnnotationState {
private:
    bool m_skip;

public:
    static const char className[];
    static Lunar<LuaInstructionAnnotationState>::RegType methods[];
    LuaInstructionAnnotationState(lua_State *L) : LuaAnnotationState(L) {
    }

    LuaInstructionAnnotationState() : LuaAnnotationState(), m_skip(false) {
    }

    bool doSkip() const {
        return m_skip;
    }

    int skipInstruction(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
