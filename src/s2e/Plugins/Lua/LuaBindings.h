///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LUABINDINGS_H
#define S2E_PLUGINS_LUABINDINGS_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include "LuaS2E.h"

namespace s2e {
namespace plugins {

/**
 *  This plugin acts as a centralized registry for all Lua bindings.
 */
class LuaBindings : public Plugin {
    S2E_PLUGIN

private:
    LuaS2E *m_luaS2E;

public:
    LuaBindings(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
};

} // namespace plugins
} // namespace s2e

#endif
