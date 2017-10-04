///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include "LuaAnnotationState.h"
#include "LuaInstructionAnnotation.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaInstructionAnnotation, "Execute Lua code on an instruction", "LuaInstructionAnnotation",
                  "LuaBindings", "ProcessExecutionDetector", "ModuleMap");

// XXX: don't duplicate with LuaFunctionAnnotation, move to ConfigFile?
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

// TODO: share some code with LuaFunctionAnnotation
void LuaInstructionAnnotation::initialize() {
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_modules = s2e()->getPlugin<ModuleMap>();

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

        std::string moduleId = readStringOrFail(s2e(), ss.str() + ".module_name");
        std::string annotationName = readStringOrFail(s2e(), ss.str() + ".name");
        uint64_t pc = readIntOrFail(s2e(), ss.str() + ".pc");

        if (!registerAnnotation(moduleId, Annotation(annotationName, pc))) {
            exit(-1);
        }
    }

    m_detector->onMonitorLoad.connect(sigc::mem_fun(*this, &LuaInstructionAnnotation::onMonitorLoad));
}

bool LuaInstructionAnnotation::registerAnnotation(const std::string &moduleId, const Annotation &annotation) {
    if (m_annotations[moduleId] == nullptr) {
        m_annotations[moduleId] = new ModuleAnnotations();
    }

    if (m_annotations[moduleId]->find(annotation) != m_annotations[moduleId]->end()) {
        getWarningsStream() << "attempting to register existing annotation\n";
        return false;
    }

    m_annotations[moduleId]->insert(annotation);

    getDebugStream() << "loaded " << moduleId << " " << annotation.annotationName << " " << hexval(annotation.pc)
                     << "\n";

    return true;
}

void LuaInstructionAnnotation::onMonitorLoad(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &LuaInstructionAnnotation::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &LuaInstructionAnnotation::onTranslateBlockComplete));
}

// XXX: what if TB is interrupt in the middle?
void LuaInstructionAnnotation::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc) {
    // TODO: decide here whether there might be an instruction
    // that can be hooked (probably will need the use of the static CFG)
    CorePlugin *plg = s2e()->getCorePlugin();
    m_instructionStart.disconnect();

    const ModuleDescriptor *module = m_modules->getModule(state, pc);
    if (!module) {
        return;
    }

    Annotations::const_iterator it = m_annotations.find(module->Name);
    if (it == m_annotations.end()) {
        return;
    }

    m_instructionStart = plg->onTranslateInstructionStart.connect(
        sigc::bind(sigc::mem_fun(*this, &LuaInstructionAnnotation::onTranslateInstructionStart), it->second,
                   (-module->LoadBase + module->NativeBase) /* Pass an addend to convert the program counter */
                   ));
}

void LuaInstructionAnnotation::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                           TranslationBlock *tb, uint64_t pc,
                                                           const ModuleAnnotations *annotations, uint64_t addend) {
    uint64_t modulePc = pc + addend;
    Annotation tofind(modulePc);

    if (annotations->find(tofind) == annotations->end()) {
        return;
    }

    signal->connect(sigc::bind(sigc::mem_fun(*this, &LuaInstructionAnnotation::onInstruction), annotations, modulePc));
}

void LuaInstructionAnnotation::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb,
                                                        uint64_t ending_pc) {
    m_instructionStart.disconnect();
}

void LuaInstructionAnnotation::onInstruction(S2EExecutionState *state, uint64_t pc,
                                             const ModuleAnnotations *annotations, uint64_t modulePc) {
    if (!m_detector->isTracked(state)) {
        return;
    }

    Annotation tofind(modulePc);
    ModuleAnnotations::const_iterator it = annotations->find(tofind);
    if (it == annotations->end()) {
        return;
    }

    getDebugStream(state) << "instruction " << hexval(modulePc) << " triggered annotation " << it->annotationName
                          << "\n";

    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState luaS2EState(state);
    LuaAnnotationState luaAnnotation;

    lua_getglobal(L, it->annotationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaAnnotationState>::push(L, &luaAnnotation);

    lua_call(L, 2, 0);

    if (luaAnnotation.exitCpuLoop()) {
        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
