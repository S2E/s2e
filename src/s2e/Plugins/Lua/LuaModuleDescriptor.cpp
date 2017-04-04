///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "LuaModuleDescriptor.h"

namespace s2e {
namespace plugins {

const char LuaModuleDescriptor::className[] = "LuaModuleDescriptor";

Lunar<LuaModuleDescriptor>::RegType LuaModuleDescriptor::methods[] = {
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getPid),
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getName),
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getNativeBase),
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getLoadBase),
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getSize),
    LUNAR_DECLARE_METHOD(LuaModuleDescriptor, getEntryPoint),
    {0, 0}};

int LuaModuleDescriptor::getPid(lua_State *L) {
    lua_pushinteger(L, m_desc.Pid);
    return 1;
}

int LuaModuleDescriptor::getName(lua_State *L) {
    lua_pushstring(L, m_desc.Name.c_str());
    return 1;
}

int LuaModuleDescriptor::getNativeBase(lua_State *L) {
    lua_pushinteger(L, m_desc.NativeBase);
    return 1;
}

int LuaModuleDescriptor::getLoadBase(lua_State *L) {
    lua_pushinteger(L, m_desc.LoadBase);
    return 1;
}

int LuaModuleDescriptor::getSize(lua_State *L) {
    lua_pushinteger(L, m_desc.Size);
    return 1;
}

int LuaModuleDescriptor::getEntryPoint(lua_State *L) {
    lua_pushinteger(L, m_desc.EntryPoint);
    return 1;
}
}
}
