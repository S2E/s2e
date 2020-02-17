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

#ifndef _LUA_MODULE_DESCRIPTOR_

#define _LUA_MODULE_DESCRIPTOR_

#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaModuleDescriptor {
private:
    ModuleDescriptorConstPtr m_desc;

public:
    static const char className[];
    static Lunar<LuaModuleDescriptor>::RegType methods[];

    LuaModuleDescriptor(lua_State *L) {
    }

    LuaModuleDescriptor(ModuleDescriptorConstPtr desc) {
        m_desc = desc;
    }

    int getPid(lua_State *L);
    int getName(lua_State *L);
    int getNativeBase(lua_State *L);
    int getLoadBase(lua_State *L);
    int getSize(lua_State *L);
    int getEntryPoint(lua_State *L);
};
} // namespace plugins
} // namespace s2e

#endif
