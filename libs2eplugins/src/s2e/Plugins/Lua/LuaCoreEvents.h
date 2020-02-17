///
/// Copyright (C) 2015, Cyberhaven
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
    std::string m_onStateForkDecide;

    void registerCoreSignals(const std::string &cfgname);
    std::string checkCoreSignal(const std::string &cfgname, const std::string &name);

    void onTimer();
    void onStateKill(S2EExecutionState *state);
    void onStateForkDecide(S2EExecutionState *state, bool *allowForking);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaCoreEvents_H
