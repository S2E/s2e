///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include "LuaAnnotationState.h"
#include "LuaFunctionAnnotation.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaFunctionAnnotation, "LuaFunctionAnnotation S2E plugin", "LuaFunctionAnnotation",
                  "ModuleExecutionDetector", "FunctionMonitor", "OSMonitor", "LuaBindings");

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
bool LuaFunctionAnnotation::registerAnnotation(const Annotation &annotation) {
    if (!m_detector->isModuleConfigured(annotation.moduleId)) {
        getWarningsStream() << "LuaFunctionAnnotation: unknown module id " << annotation.moduleId << "\n";
        return false;
    }

    foreach2 (ait, m_annotations.begin(), m_annotations.end()) {
        if (*(*ait) == annotation) {
            getWarningsStream() << "LuaFunctionAnnotation: attempting to register existing annotation\n";
            return false;
        }
    }

    m_annotations.push_back(new Annotation(annotation));

    getDebugStream() << "LuaFunctionAnnotation: loaded " << annotation.moduleId << " " << annotation.annotationName
                     << " " << hexval(annotation.pc) << " "
                     << "convention: " << annotation.convention << "\n";
    return true;
}

void LuaFunctionAnnotation::initialize() {
    m_monitor = dynamic_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_detector = static_cast<ModuleExecutionDetector *>(s2e()->getPlugin("ModuleExecutionDetector"));
    m_functionMonitor = static_cast<FunctionMonitor *>(s2e()->getPlugin("FunctionMonitor"));
    m_kvs = static_cast<KeyValueStore *>(s2e()->getPlugin("KeyValueStore"));

    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey() + ".annotations", &ok);
    if (!ok) {
        getWarningsStream() << "LuaFunctionAnnotation: must have an .annotations section\n";
        exit(-1);
    }

    foreach2 (kit, keys.begin(), keys.end()) {
        std::stringstream ss;
        ss << getConfigKey() << ".annotations." << *kit;
        Annotation annotation;
        annotation.moduleId = readStringOrFail(s2e(), ss.str() + ".module_id");
        annotation.annotationName = readStringOrFail(s2e(), ss.str() + ".name");
        annotation.pc = readIntOrFail(s2e(), ss.str() + ".pc");
        annotation.paramCount = readIntOrFail(s2e(), ss.str() + ".param_count");
        annotation.fork = readBoolOrFail(s2e(), ss.str() + ".fork");
        std::string cc = readStringOrFail(s2e(), ss.str() + ".convention");

        if (cc == "stdcall") {
            annotation.convention = STDCALL;
        } else if (cc == "cdecl") {
            annotation.convention = CDECL;
        } else {
            getWarningsStream() << "LuaFunctionAnnotation: unknown convention" << cc << "\n";
            exit(-1);
        }

        if (!registerAnnotation(annotation)) {
            exit(-1);
        }
    }

    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &LuaFunctionAnnotation::onModuleLoad));

    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &LuaFunctionAnnotation::onModuleUnload));
}

void LuaFunctionAnnotation::hookAnnotation(S2EExecutionState *state, const ModuleDescriptor &module,
                                           const Annotation *annotation) {
    FunctionMonitor::CallSignal *cs;
    uint64_t funcPc = module.ToRuntime(annotation->pc);
    cs = m_functionMonitor->getCallSignal(state, funcPc, m_monitor->getPid(state, funcPc));
    cs->connect(sigc::bind(sigc::mem_fun(*this, &LuaFunctionAnnotation::onFunctionCall), annotation));
}

void LuaFunctionAnnotation::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    // Register all function hooks
    const std::string *mid = m_detector->getModuleId(module);
    if (!mid) {
        return;
    }

    foreach2 (ait, m_annotations.begin(), m_annotations.end()) {
        const Annotation *annotation = *ait;
        if (annotation->moduleId != *mid) {
            continue;
        }

        hookAnnotation(state, module, annotation);
    }
}

void LuaFunctionAnnotation::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    // Remove all function hooks
    m_functionMonitor->disconnect(state, module);
}

void LuaFunctionAnnotation::forkAnnotation(S2EExecutionState *state, const Annotation &entry) {
    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationState, p, state);
    if (p->isChild()) {
        return;
    }

    std::stringstream ss;
    ss << "annotation_" << entry.annotationName << "_child";

    /* Use the KVS to make sure that we exercise the annotated function only once */
    if (m_kvs) {
        bool exists = false;
        m_kvs->put(ss.str(), "1", exists);
        if (exists) {
            return;
        }
    }

    klee::ref<klee::Expr> cond = state->createConcolicValue<uint8_t>(ss.str(), 0);
    cond = klee::Expr::createIsZero(cond);
    S2EExecutor::StatePair sp = g_s2e->getExecutor()->forkCondition(state, cond);
    S2EExecutionState *s1 = static_cast<S2EExecutionState *>(sp.first);
    S2EExecutionState *s2 = static_cast<S2EExecutionState *>(sp.second);

    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationState, p1, s1);
    p1->m_child = false;

    DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationState, p2, s2);
    p2->m_child = true;
}

void LuaFunctionAnnotation::invokeAnnotation(S2EExecutionState *state, const Annotation &entry, bool isCall) {
    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState lua_s2e_state(state);
    LuaAnnotationState luaAnnotation;

    if (isCall && entry.fork) {
        DECLARE_PLUGINSTATE_N(LuaFunctionAnnotationState, p, state);
        forkAnnotation(state, entry);

        luaAnnotation.setChild(p->isChild());
        p->m_child = false;
    }

    lua_getglobal(L, entry.annotationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &lua_s2e_state);
    Lunar<LuaAnnotationState>::push(L, &luaAnnotation);

    if (entry.paramCount > 0 && state->getPointerSize() == 8) {
        g_s2e->getExecutor()->terminateStateEarly(*state, "LuaFunctionAnnotation: 64-bits support not implemented");
    }

    lua_pushboolean(L, isCall);

    uint64_t pointerSize = state->getPointerSize();
    uint64_t paramSp = state->getSp();
    paramSp += pointerSize;

    for (unsigned i = 0; i < entry.paramCount; ++i) {
        uint64_t address = paramSp + i * pointerSize;
        lua_pushinteger(L, address);
    }

    lua_call(L, 3 + entry.paramCount, 0);

    if (luaAnnotation.exitCpuLoop()) {
        throw CpuExitException();
    }

    if (luaAnnotation.doSkip()) {
        m_functionMonitor->eraseSp(state, state->regs()->getSp());

        if (entry.convention == STDCALL) {
            state->bypassFunction(entry.paramCount);
        } else {
            state->bypassFunction(0);
        }

        throw CpuExitException();
    }
}

void LuaFunctionAnnotation::onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns,
                                           const Annotation *entry) {
    state->undoCallAndJumpToSymbolic();
    getDebugStream() << "LuaFunctionAnnotation: Invoking call annotation " << entry->annotationName << '\n';

    FunctionMonitor::ReturnSignal returnSignal;
    returnSignal.connect(sigc::bind(sigc::mem_fun(*this, &LuaFunctionAnnotation::onFunctionRet), entry));
    fns->registerReturnSignal(state, returnSignal);

    invokeAnnotation(state, *entry, true);
}

void LuaFunctionAnnotation::onFunctionRet(S2EExecutionState *state, const Annotation *entry) {
    state->jumpToSymbolicCpp();
    getDebugStream() << "LuaFunctionAnnotation: Invoking return annotation " << entry->annotationName << '\n';
    invokeAnnotation(state, *entry, false);
}

/*************************************************************************/

LuaFunctionAnnotationState::LuaFunctionAnnotationState() {
    m_child = false;
}

LuaFunctionAnnotationState::~LuaFunctionAnnotationState() {
}

LuaFunctionAnnotationState *LuaFunctionAnnotationState::clone() const {
    return new LuaFunctionAnnotationState(*this);
}

PluginState *LuaFunctionAnnotationState::factory(Plugin *p, S2EExecutionState *s) {
    return new LuaFunctionAnnotationState();
}

} // namespace plugins
} // namespace s2e
