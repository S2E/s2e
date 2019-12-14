///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/Support/KeyValueStore.h>

#include "LuaFunctionAnnotation.h"
#include "LuaFunctionAnnotationState.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaFunctionAnnotation, "Execute Lua code on a function call", "LuaFunctionAnnotation",
                  "FunctionMonitor", "LuaBindings");

class LuaFunctionAnnotationPluginState : public PluginState {
private:
    bool m_child;

public:
    LuaFunctionAnnotationPluginState() : m_child(false){};

    virtual LuaFunctionAnnotationPluginState *clone() const {
        return new LuaFunctionAnnotationPluginState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LuaFunctionAnnotationPluginState();
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
        s2e->getWarningsStream() << "LuaFunctionAnnotation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

static uint64_t readIntOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    uint64_t ret = cfg->getInt(key, 0, &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionAnnotation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

static bool readBoolOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    bool ret = cfg->getBool(key, 0, &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionAnnotation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

void LuaFunctionAnnotation::initialize() {
    m_functionMonitor = s2e()->getPlugin<FunctionMonitor>();
    m_kvs = s2e()->getPlugin<KeyValueStore>();

    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey() + ".annotations", &ok);
    if (!ok) {
        getWarningsStream() << "must have an .annotations section\n";
        exit(-1);
    }

    for (auto const &key : keys) {
        std::stringstream ss;
        ss << getConfigKey() << ".annotations." << key;

        std::string moduleName = readStringOrFail(s2e(), ss.str() + ".module_name");
        std::string annotationName = readStringOrFail(s2e(), ss.str() + ".name");
        uint64_t pc = readIntOrFail(s2e(), ss.str() + ".pc");
        unsigned paramCount = readIntOrFail(s2e(), ss.str() + ".param_count");
        bool fork = readBoolOrFail(s2e(), ss.str() + ".fork");
        std::string cc = readStringOrFail(s2e(), ss.str() + ".convention");

        Annotation::CallingConvention convention;
        if (cc == "stdcall") {
            convention = Annotation::STDCALL;
        } else if (cc == "cdecl") {
            convention = Annotation::CDECL;
        } else {
            getWarningsStream() << "unknown calling convention" << cc << "\n";
            exit(-1);
        }

        if (!registerAnnotation(Annotation(moduleName, pc, paramCount, annotationName, convention, fork))) {
            exit(-1);
        }
    }

    m_functionMonitor->onCall.connect(sigc::mem_fun(*this, &LuaFunctionAnnotation::onCall));
}

void LuaFunctionAnnotation::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                   const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                                   const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!dest) {
        return;
    }

    // TODO: need faster annotation lookup
    for (auto const &annotation : m_annotations) {
        if (annotation->pc == calleePc && annotation->moduleName == dest->Name) {
            invokeAnnotation(state, *annotation, true);
            returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &LuaFunctionAnnotation::onRet), annotation));
        }
    }
}

void LuaFunctionAnnotation::onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                  const ModuleDescriptorConstPtr &dest, uint64_t returnSite, AnnotationPtr annotation) {
    invokeAnnotation(state, *annotation, false);
}

bool LuaFunctionAnnotation::registerAnnotation(const Annotation &annotation) {
    for (auto const &annot : m_annotations) {
        if (*annot == annotation) {
            getWarningsStream() << "attempting to register existing annotation\n";

            return false;
        }
    }

    m_annotations.push_back(std::make_shared<Annotation>(annotation));

    getDebugStream() << "loaded " << annotation.annotationName << " " << annotation.moduleName << "!"
                     << hexval(annotation.pc) << " convention: " << annotation.convention << "\n";

    return true;
}

void LuaFunctionAnnotation::forkAnnotation(S2EExecutionState *state, const Annotation &entry) {
    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationPluginState, p, state);
    if (p->isChild()) {
        return;
    }

    std::stringstream ss;
    ss << "annotation_" << entry.annotationName << "_child";

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

    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationPluginState, p1, s1);
    p1->makeChild(false);

    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationPluginState, p2, s2);
    p2->makeChild(true);
}

void LuaFunctionAnnotation::invokeAnnotation(S2EExecutionState *state, const Annotation &entry, bool isCall) {
    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState luaS2EState(state);
    LuaFunctionAnnotationState luaAnnotation;

    if (isCall && entry.fork) {
        DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationPluginState, p, state);
        forkAnnotation(state, entry);

        luaAnnotation.setChild(p->isChild());
        p->makeChild(false);
    }

    lua_getglobal(L, entry.annotationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaFunctionAnnotationState>::push(L, &luaAnnotation);

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

    if (luaAnnotation.exitCpuLoop()) {
        throw CpuExitException();
    }

    if (isCall && luaAnnotation.doSkip()) {
        if (entry.convention == Annotation::STDCALL) {
            state->bypassFunction(entry.paramCount);
        } else {
            state->bypassFunction(0);
        }

        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
