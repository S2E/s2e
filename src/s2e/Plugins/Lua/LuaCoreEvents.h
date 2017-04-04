///
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LuaCoreEvents_H
#define S2E_PLUGINS_LuaCoreEvents_H

#include <string>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include "Lua.h"

namespace s2e {
namespace plugins {

class LuaCoreEvents : public Plugin {
    S2E_PLUGIN
public:
    LuaCoreEvents(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    std::string m_onStateKill;
    std::string m_onTimer;

    void registerCoreSignals(const std::string &cfgname);
    std::string checkCoreSignal(const std::string &cfgname, const std::string &name);

    void onTimer();
    void onStateKill(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaCoreEvents_H
