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
    lua_pushinteger(L, m_desc->Pid);
    return 1;
}

int LuaModuleDescriptor::getName(lua_State *L) {
    lua_pushstring(L, m_desc->Name.c_str());
    return 1;
}

int LuaModuleDescriptor::getNativeBase(lua_State *L) {
    lua_pushinteger(L, m_desc->NativeBase);
    return 1;
}

int LuaModuleDescriptor::getLoadBase(lua_State *L) {
    lua_pushinteger(L, m_desc->LoadBase);
    return 1;
}

int LuaModuleDescriptor::getSize(lua_State *L) {
    lua_pushinteger(L, m_desc->Size);
    return 1;
}

int LuaModuleDescriptor::getEntryPoint(lua_State *L) {
    lua_pushinteger(L, m_desc->EntryPoint);
    return 1;
}
} // namespace plugins
} // namespace s2e
