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

#include "LuaAnnotationState.h"
#include "LuaInstructionAnnotation.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaInstructionAnnotation, "Plugin to annotate instructions", "LuaInstructionAnnotation",
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
        getWarningsStream() << "LuaInstructionAnnotation: must have an .annotations section\n";
        exit(-1);
    }

    foreach2 (kit, keys.begin(), keys.end()) {
        std::stringstream ss;
        ss << getConfigKey() << ".annotations." << *kit;

        std::string moduleId = readStringOrFail(s2e(), ss.str() + ".module_name");

        Annotation annotation;
        annotation.annotationName = readStringOrFail(s2e(), ss.str() + ".name");
        annotation.pc = readIntOrFail(s2e(), ss.str() + ".pc");

        if (!registerAnnotation(moduleId, annotation)) {
            exit(-1);
        }
    }

    m_detector->onMonitorLoad.connect(sigc::mem_fun(*this, &LuaInstructionAnnotation::onMonitorLoad));
}

bool LuaInstructionAnnotation::registerAnnotation(const std::string &moduleId, const Annotation &annotation) {
    if (m_annotations[moduleId] == NULL) {
        m_annotations[moduleId] = new ModuleAnnotations();
    }

    if (m_annotations[moduleId]->find(annotation) != m_annotations[moduleId]->end()) {
        getWarningsStream() << "LuaInstructionAnnotation: attempting to register existing annotation\n";
        return false;
    }

    m_annotations[moduleId]->insert(annotation);

    getDebugStream() << "LuaInstructionAnnotation: loaded " << moduleId << " " << annotation.annotationName << " "
                     << hexval(annotation.pc) << "\n";
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
        sigc::bind(sigc::mem_fun(*this, &LuaInstructionAnnotation::onTranslateInstructionStart), (*it).second,
                   (-module->LoadBase + module->NativeBase) /* Pass an addend to convert the program counter */
                   ));
}

void LuaInstructionAnnotation::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                           TranslationBlock *tb, uint64_t pc,
                                                           const ModuleAnnotations *annotations, uint64_t addend) {
    uint64_t modulePc = pc + addend;
    Annotation tofind;
    tofind.pc = modulePc;
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

    Annotation tofind;
    tofind.pc = modulePc;
    ModuleAnnotations::const_iterator it = annotations->find(tofind);
    if (it == annotations->end()) {
        return;
    }

    getDebugStream(state) << "LuaInstructionAnnotation: instruction " << hexval(modulePc) << " triggered annotation "
                          << (*it).annotationName << "\n";

    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState lua_s2e_state(state);
    LuaAnnotationState luaAnnotation;

    lua_getglobal(L, (*it).annotationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &lua_s2e_state);
    Lunar<LuaAnnotationState>::push(L, &luaAnnotation);

    lua_call(L, 2, 0);

    if (luaAnnotation.exitCpuLoop()) {
        throw CpuExitException();
    }
}

void LuaInstructionAnnotation::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                      uint64_t guestDataSize) {
    S2E_LUA_INS_ANN_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "LuaInstructionAnnotation: mismatched S2E_LUA_INS_ANN_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "LuaInstructionAnnotation: could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case REGISTER_ANNOTATION: {
            Annotation annotation;
            bool ok = true;

            const ModuleDescriptor *module = m_modules->getModule(state, command.RegisterAnnotation.Pc);
            if (!module) {
                command.Result = 0;
                break;
            }

            ok &= state->mem()->readString(command.RegisterAnnotation.AnnotationNameStr, annotation.annotationName);
            annotation.pc = command.RegisterAnnotation.Pc;

            if (!ok) {
                command.Result = 0;
            } else {
                command.Result = 1;
                command.Result = registerAnnotation(module->Name, annotation);
            }
        } break;

        default: {
            getWarningsStream(state) << "LuaInstructionAnnotation: incorrect command " << command.Command << "\n";
        }
    }

    state->mem()->writeMemoryConcrete(guestDataPtr, &command, guestDataSize);
}

} // namespace plugins
} // namespace s2e
