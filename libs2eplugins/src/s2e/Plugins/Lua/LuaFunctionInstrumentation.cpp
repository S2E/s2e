///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/Support/KeyValueStore.h>

#include "LuaFunctionInstrumentation.h"
#include "LuaFunctionInstrumentationState.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaFunctionInstrumentation, "Execute Lua code on a function call", "LuaFunctionInstrumentation",
                  "FunctionMonitor", "LuaBindings");

class LuaFunctionInstrumentationPluginState : public PluginState {
private:
    bool m_child;

public:
    LuaFunctionInstrumentationPluginState() : m_child(false){};

    virtual LuaFunctionInstrumentationPluginState *clone() const {
        return new LuaFunctionInstrumentationPluginState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LuaFunctionInstrumentationPluginState();
    }

    bool isChild() const {
        return m_child;
    }

    void makeChild(bool child) {
        m_child = child;
    }
};

/*************************************************************************/

static std::string readStringOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    std::string ret = cfg->getString(key, "", &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionInstrumentation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

static uint64_t readIntOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    uint64_t ret = cfg->getInt(key, 0, &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionInstrumentation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

static bool readBoolOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    bool ret = cfg->getBool(key, 0, &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionInstrumentation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

void LuaFunctionInstrumentation::initialize() {
    m_functionMonitor = s2e()->getPlugin<FunctionMonitor>();
    m_kvs = s2e()->getPlugin<KeyValueStore>();

    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey() + ".instrumentation", &ok);
    if (!ok) {
        getWarningsStream() << "must have an .instrumentation section\n";
        exit(-1);
    }

    for (auto const &key : keys) {
        std::stringstream ss;
        ss << getConfigKey() << ".instrumentation." << key;

        std::string moduleName = readStringOrFail(s2e(), ss.str() + ".module_name");
        std::string instrumentationName = readStringOrFail(s2e(), ss.str() + ".name");
        uint64_t pc = readIntOrFail(s2e(), ss.str() + ".pc");
        unsigned paramCount = readIntOrFail(s2e(), ss.str() + ".param_count");
        bool fork = readBoolOrFail(s2e(), ss.str() + ".fork");
        std::string cc = readStringOrFail(s2e(), ss.str() + ".convention");

        Instrumentation::CallingConvention convention;
        if (cc == "stdcall") {
            convention = Instrumentation::STDCALL;
        } else if (cc == "cdecl") {
            convention = Instrumentation::CDECL;
        } else {
            getWarningsStream() << "unknown calling convention" << cc << "\n";
            exit(-1);
        }

        if (!registerInstrumentation(
                Instrumentation(moduleName, pc, paramCount, instrumentationName, convention, fork))) {
            exit(-1);
        }
    }

    m_functionMonitor->onCall.connect(sigc::mem_fun(*this, &LuaFunctionInstrumentation::onCall));
}

void LuaFunctionInstrumentation::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                        const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                                        const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!dest) {
        return;
    }

    // TODO: need faster lookup
    for (auto const &instrumentation : m_instrumentations) {
        if (instrumentation->pc == calleePc && instrumentation->moduleName == dest->Name) {
            invokeInstrumentation(state, *instrumentation, true);
            returnSignal->connect(
                sigc::bind(sigc::mem_fun(*this, &LuaFunctionInstrumentation::onRet), instrumentation));
        }
    }
}

void LuaFunctionInstrumentation::onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                       const ModuleDescriptorConstPtr &dest, uint64_t returnSite,
                                       InstrumentationPtr instrumentation) {
    invokeInstrumentation(state, *instrumentation, false);
}

bool LuaFunctionInstrumentation::registerInstrumentation(const Instrumentation &instrumentation) {
    for (auto const &annot : m_instrumentations) {
        if (*annot == instrumentation) {
            getWarningsStream() << "attempting to register existing instrumentation\n";

            return false;
        }
    }

    m_instrumentations.push_back(std::make_shared<Instrumentation>(instrumentation));

    getDebugStream() << "loaded " << instrumentation.instrumentationName << " " << instrumentation.moduleName << "!"
                     << hexval(instrumentation.pc) << " convention: " << instrumentation.convention << "\n";

    return true;
}

void LuaFunctionInstrumentation::forkInstrumentation(S2EExecutionState *state, const Instrumentation &entry) {
    DECLARE_PLUGINSTATE_N(LuaFunctionInstrumentationPluginState, p, state);
    if (p->isChild()) {
        return;
    }

    std::stringstream ss;
    ss << "instrumentation_" << entry.instrumentationName << "_child";

    // Use the KVS to make sure that we exercise the annotated function only once
    if (m_kvs) {
        bool exists = false;
        m_kvs->put(ss.str(), "1", exists);
        if (exists) {
            return;
        }
    }

    klee::ref<klee::Expr> cond = state->createSymbolicValue<uint8_t>(ss.str(), 0);
    cond = klee::Expr::createIsZero(cond);
    S2EExecutor::StatePair sp = s2e()->getExecutor()->forkCondition(state, cond);
    S2EExecutionState *s1 = static_cast<S2EExecutionState *>(sp.first);
    S2EExecutionState *s2 = static_cast<S2EExecutionState *>(sp.second);

    DECLARE_PLUGINSTATE_N(LuaFunctionInstrumentationPluginState, p1, s1);
    p1->makeChild(false);

    DECLARE_PLUGINSTATE_N(LuaFunctionInstrumentationPluginState, p2, s2);
    p2->makeChild(true);
}

void LuaFunctionInstrumentation::invokeInstrumentation(S2EExecutionState *state, const Instrumentation &entry,
                                                       bool isCall) {
    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState luaS2EState(state);
    LuaFunctionInstrumentationState luaInstrumentation;

    if (isCall && entry.fork) {
        DECLARE_PLUGINSTATE_N(LuaFunctionInstrumentationPluginState, p, state);
        forkInstrumentation(state, entry);

        luaInstrumentation.setChild(p->isChild());
        p->makeChild(false);
    }

    lua_getglobal(L, entry.instrumentationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaFunctionInstrumentationState>::push(L, &luaInstrumentation);

    if (entry.paramCount > 0 && state->getPointerSize() == 8) {
        s2e()->getExecutor()->terminateState(*state, "64-bit support not implemented");
    }

    lua_pushboolean(L, isCall);

    uint64_t pointerSize = state->getPointerSize();
    uint64_t paramSp = state->regs()->getSp() + pointerSize;

    for (unsigned i = 0; i < entry.paramCount; ++i) {
        uint64_t address = paramSp + i * pointerSize;
        lua_pushinteger(L, address);
    }

    lua_call(L, 3 + entry.paramCount, 0);

    if (luaInstrumentation.exitCpuLoop()) {
        throw CpuExitException();
    }

    if (isCall && luaInstrumentation.doSkip()) {
        if (entry.convention == Instrumentation::STDCALL) {
            state->bypassFunction(entry.paramCount);
        } else {
            state->bypassFunction(0);
        }

        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
