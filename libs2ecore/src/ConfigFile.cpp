///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <sstream>
#include <stdlib.h>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <s2e/ConfigFile.h>

namespace s2e {
using namespace std;

ConfigFile::ConfigFile(const std::string &configFileName) {
    m_silent = false;
    m_luaState = luaL_newstate();
    luaL_openlibs(m_luaState);
    luaopen_table(m_luaState);
    luaopen_string(m_luaState);
    luaopen_debug(m_luaState);

    if (!configFileName.empty()) {
        if (luaL_loadfile(m_luaState, configFileName.c_str()) || lua_pcall(m_luaState, 0, 0, 0)) {
            luaError("Can not run configuration file:\n    %s\n", lua_tostring(m_luaState, -1));
        }
    }
}

ConfigFile::~ConfigFile() {
    lua_close(m_luaState);
}

template <> inline const char *ConfigFile::getTypeName<bool>() {
    return "boolean";
}

template <> inline const char *ConfigFile::getTypeName<int64_t>() {
    return "integer";
}

template <> inline const char *ConfigFile::getTypeName<double>() {
    return "double";
}

template <> inline const char *ConfigFile::getTypeName<string>() {
    return "string";
}

template <> inline const char *ConfigFile::getTypeName<ConfigFile::string_list>() {
    return "lua_list with only string values";
}

template <> inline const char *ConfigFile::getTypeName<ConfigFile::integer_list>() {
    return "lua_list with only integer values";
}

template <> inline const char *ConfigFile::getTypeName<ConfigFile::_key_list>() {
    return "lua_table with only string keys";
}

template <> inline const char *ConfigFile::getTypeName<ConfigFile::_list_size>() {
    return "lua_table";
}

template <> inline bool ConfigFile::getLuaValue(bool *res, const bool &def, int index) {
    bool ok = lua_isboolean(m_luaState, index);
    *res = ok ? lua_toboolean(m_luaState, index) : def;
    return ok;
}

template <> inline bool ConfigFile::getLuaValue(int64_t *res, const int64_t &def, int index) {
    bool ok = lua_isnumber(m_luaState, index);
    *res = ok ? lua_tointeger(m_luaState, index) : def;
    return ok;
}

template <> inline bool ConfigFile::getLuaValue(double *res, const double &def, int index) {
    bool ok = lua_isnumber(m_luaState, index);
    *res = ok ? lua_tonumber(m_luaState, index) : def;
    return ok;
}

template <> inline bool ConfigFile::getLuaValue(string *res, const string &def, int index) {
    bool ok = lua_isstring(m_luaState, index);
    *res = ok ? lua_tostring(m_luaState, index) : def;
    return ok;
}

template <> inline bool ConfigFile::getLuaValue(string_list *res, const string_list &def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if (!ok) {
        *res = def;
        return ok;
    }

    /* read table as array */
    for (int i = 1;; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if (lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        if (lua_isstring(m_luaState, -1)) {
            res->push_back(lua_tostring(m_luaState, -1));
            lua_pop(m_luaState, 1);
        } else {
            lua_pop(m_luaState, 1);
            *res = def;
            return false;
        }
    }

    return true;
}

template <> inline bool ConfigFile::getLuaValue(integer_list *res, const integer_list &def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if (!ok) {
        *res = def;
        return ok;
    }

    /* read table as array */
    for (int i = 1;; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if (lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        if (lua_isstring(m_luaState, -1)) {
            res->push_back(lua_tointeger(m_luaState, -1));
            lua_pop(m_luaState, 1);
        } else {
            lua_pop(m_luaState, 1);
            *res = def;
            return false;
        }
    }

    return true;
}

template <> inline bool ConfigFile::getLuaValue(_list_size *res, const _list_size &def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if (!ok) {
        *res = def;
        return ok;
    }

    /* read table as array */
    res->size = 0;
    for (int i = 1;; ++i) {
        lua_rawgeti(m_luaState, index, i);
        if (lua_isnil(m_luaState, -1)) {
            lua_pop(m_luaState, 1);
            break;
        }
        res->size += 1;
        lua_pop(m_luaState, 1);
    }

    return true;
}

template <> inline bool ConfigFile::getLuaValue(_key_list *res, const _key_list &def, int index) {
    bool ok = lua_istable(m_luaState, index);
    if (!ok) {
        *res = def;
        return ok;
    }

    lua_pushnil(m_luaState); /* first key */

    /* table is in the stack at index-1 */
    while (lua_next(m_luaState, index - 1) != 0) {
        /* uses 'key' (at index -2) and 'value' (at index -1) */

        if (!lua_isstring(m_luaState, -2)) {
            *res = def;
            return false;
        }

        res->keys.push_back(lua_tostring(m_luaState, -2));

        /* removes 'value'; keeps 'key' for next iteration */
        lua_pop(m_luaState, 1);
    }

    return true;
}

template <typename T> inline T ConfigFile::getValueT(const std::string &name, const T &def, bool *ok) {
    assert(name.size() != 0);
    string expr = "return " + name;

    if (luaL_loadstring(m_luaState, expr.c_str()) || lua_pcall(m_luaState, 0, 1, 0)) {
        if (!m_silent) {
            luaWarning("Cannot get configuration value '%s':\n    %s\n", name.c_str(), lua_tostring(m_luaState, -1));
        }
        lua_pop(m_luaState, 1);
        if (ok)
            *ok = false;
        return def;
    }

    T res;
    bool _ok = getLuaValue(&res, def, -1);
    if (ok)
        *ok = _ok;

    if (!_ok && !m_silent) {
        luaWarning("Cannot get configuration value '%s':\n    "
                   "value of type %s can not be converted to %s\n",
                   name.c_str(), lua_typename(m_luaState, lua_type(m_luaState, -1)), getTypeName<T>());
    }

    lua_pop(m_luaState, 1);
    return res;
}

bool ConfigFile::getBool(const string &name, bool def, bool *ok) {
    return getValueT(name, def, ok);
}

int64_t ConfigFile::getInt(const string &name, int64_t def, bool *ok) {
    return getValueT(name, def, ok);
}

double ConfigFile::getDouble(const string &name, double def, bool *ok) {
    return getValueT(name, def, ok);
}

string ConfigFile::getString(const string &name, const string &def, bool *ok) {
    return getValueT(name, def, ok);
}

ConfigFile::string_list ConfigFile::getStringList(const std::string &name, const string_list &def, bool *ok) {
    return getValueT(name, def, ok);
}

ConfigFile::integer_list ConfigFile::getIntegerList(const std::string &name, const integer_list &def, bool *ok) {
    return getValueT(name, def, ok);
}

int ConfigFile::getListSize(const std::string &name, bool *ok) {
    static const _list_size l = {0};
    return getValueT(name, l, ok).size;
}

ConfigFile::string_list ConfigFile::getListKeys(const std::string &name, bool *ok) {
    static const _key_list l = {std::vector<std::string>(0)};
    return getValueT(name, l, ok).keys;
}

bool ConfigFile::setBool(const string &name, bool value) {
    assert(name.size() != 0);
    std::stringstream expr;
    expr << name << " = " << (value ? "true" : "false");

    // TODO: factor this out for other types
    if (luaL_loadstring(m_luaState, expr.str().c_str()) || lua_pcall(m_luaState, 0, 1, 0)) {

        if (!m_silent) {
            luaWarning("Cannot get configuration value '%s':\n    %s\n", name.c_str(), lua_tostring(m_luaState, -1));
        }

        lua_pop(m_luaState, 1);
        return false;
    }

    return true;
}

bool ConfigFile::hasKey(const std::string &name) {
    assert(name.size() != 0);
    string expr = "return " + name;

    if (luaL_loadstring(m_luaState, expr.c_str()) || lua_pcall(m_luaState, 0, 1, 0))
        return false;

    bool ok = !lua_isnil(m_luaState, -1);
    lua_pop(m_luaState, 1);

    return ok;
}

void ConfigFile::invokeLuaCommand(const char *cmd) {
    if (luaL_dostring(m_luaState, cmd)) {
        luaWarning("Could not run '%s':\n    %s\n", cmd, lua_tostring(m_luaState, -1));
        // lua_pop(m_luaState, 1);
    }
}

bool ConfigFile::isFunctionDefined(const std::string &name) const {
    bool ret = true;
    lua_State *L = m_luaState;
    lua_getglobal(L, name.c_str());
    if (lua_isnil(L, -1)) {
        ret = false;
    }
    lua_pop(L, 1);

    return ret;
}

///////////////////////////////////////////////////////
void ConfigFile::luaError(const char *fmt, ...) {
    va_list v;
    va_start(v, fmt);

    if (g_s2e) {
        char str[512];
        vsnprintf(str, sizeof(str), fmt, v);
        g_s2e->getInfoStream() << "ERROR: " << str << '\n';
    } else {
        vfprintf(stderr, fmt, v);
    }
    va_end(v);
    lua_close(m_luaState);
    exit(1);
}

void ConfigFile::luaWarning(const char *fmt, ...) {
    va_list v;
    va_start(v, fmt);

    if (g_s2e) {
        char str[512];
        vsnprintf(str, sizeof(str), fmt, v);
        g_s2e->getWarningsStream() << "WARNING: " << str << '\n';
    } else {
        vfprintf(stderr, fmt, v);
    }
    va_end(v);
}

} // namespace s2e
