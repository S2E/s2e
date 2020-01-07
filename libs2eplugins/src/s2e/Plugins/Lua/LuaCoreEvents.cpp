///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include "LuaCoreEvents.h"
#include "LuaInstrumentationState.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaCoreEvents, "Exposes core events to lua scripts", "", "LuaBindings");

void LuaCoreEvents::initialize() {
    getInfoStream() << "Registering instrumentation for core signals\n";
    registerCoreSignals(getConfigKey());
}

std::string LuaCoreEvents::checkCoreSignal(const std::string &cfgname, const std::string &name) {
    ConfigFile *cfg = s2e()->getConfig();
    std::stringstream ss;
    ss << cfgname << "." << name;
    std::string ret = cfg->getString(ss.str());
    if (ret.length() > 0) {
        if (!cfg->isFunctionDefined(ret)) {
            getWarningsStream() << ret << " is not declared in the Lua script\n";
            exit(-1);
        }

        getDebugStream() << "Registering " << name << "(" << ret << ")\n";
    }
    return ret;
}

void LuaCoreEvents::registerCoreSignals(const std::string &cfgname) {
    m_onStateForkDecide = checkCoreSignal(cfgname, "onStateForkDecide");
    if (m_onStateForkDecide.length() > 0) {
        s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &LuaCoreEvents::onStateForkDecide));
    }

    m_onStateKill = checkCoreSignal(cfgname, "onStateKill");
    if (m_onStateKill.length() > 0) {
        s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &LuaCoreEvents::onStateKill));
    }

    m_onTimer = checkCoreSignal(cfgname, "onTimer");
    if (m_onTimer.length() > 0) {
        s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &LuaCoreEvents::onTimer));
    }
}

void LuaCoreEvents::onStateForkDecide(S2EExecutionState *state, bool *allowForking) {
    lua_State *L = s2e()->getConfig()->getState();
    LuaS2EExecutionState luaS2EState(state);
    LuaInstrumentationState luaInstrumentation;

    lua_getglobal(L, m_onStateForkDecide.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaInstrumentationState>::push(L, &luaInstrumentation);

    lua_call(L, 2, 1);
    *allowForking = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);

    if (!*allowForking) {
        s2e()->getInfoStream() << "instrumentation prevented forking at pc=" << hexval(state->regs()->getPc()) << "\n";
    }
}

void LuaCoreEvents::onStateKill(S2EExecutionState *state) {
    lua_State *L = s2e()->getConfig()->getState();
    LuaS2EExecutionState luaS2EState(state);
    LuaInstrumentationState luaInstrumentation;

    lua_getglobal(L, m_onStateKill.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaInstrumentationState>::push(L, &luaInstrumentation);

    lua_call(L, 2, 0);

    if (luaInstrumentation.exitCpuLoop()) {
        throw CpuExitException();
    }
}

void LuaCoreEvents::onTimer() {
    lua_State *L = s2e()->getConfig()->getState();
    LuaInstrumentationState luaInstrumentation;

    lua_getglobal(L, m_onTimer.c_str());
    Lunar<LuaInstrumentationState>::push(L, &luaInstrumentation);

    lua_call(L, 1, 0);

    if (luaInstrumentation.exitCpuLoop()) {
        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
