///
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LuaInstructionAnnotation_H
#define S2E_PLUGINS_LuaInstructionAnnotation_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class ModuleMap;
class ProcessExecutionDetector;

class LuaInstructionAnnotation : public Plugin {
    S2E_PLUGIN

public:
    LuaInstructionAnnotation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    struct Annotation {
        const std::string annotationName;
        const uint64_t pc;

        Annotation(std::string name, uint64_t pc_) : annotationName(name), pc(pc_) {
        }

        Annotation(uint64_t pc_) : Annotation("", pc_) {
        }

        bool operator==(const Annotation &a1) const {
            return pc == a1.pc && annotationName == a1.annotationName;
        }

        bool operator<(const Annotation &a1) const {
            return pc < a1.pc;
        }
    };

    typedef std::set<Annotation> ModuleAnnotations;
    typedef std::map<std::string, ModuleAnnotations *> Annotations;
    Annotations m_annotations;

    ProcessExecutionDetector *m_detector;
    ModuleMap *m_modules;
    sigc::connection m_instructionStart;

    bool registerAnnotation(const std::string &moduleId, const Annotation &annotation);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc, const ModuleAnnotations *annotations, uint64_t addend);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t ending_pc);

    void onInstruction(S2EExecutionState *state, uint64_t pc, const ModuleAnnotations *annotations, uint64_t modulePc);

    void onMonitorLoad(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaInstructionAnnotation_H
