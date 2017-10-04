///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LuaFunctionAnnotation_H
#define S2E_PLUGINS_LuaFunctionAnnotation_H

#include <s2e/Plugin.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class FunctionMonitor;
class FunctionMonitorState;
class KeyValueStore;
class ModuleExecutionDetector;
class OSMonitor;

class LuaFunctionAnnotation : public Plugin {
    S2E_PLUGIN

public:
    LuaFunctionAnnotation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    struct Annotation {
        enum CallingConvention { STDCALL, CDECL, MAX_CONV };

        const std::string moduleId;
        const uint64_t pc;
        const unsigned paramCount;
        const std::string annotationName;
        const CallingConvention convention;
        const bool fork;

        Annotation(std::string id, uint64_t pc_, unsigned pCount, std::string name, CallingConvention cc, bool fork_)
            : moduleId(id), pc(pc_), paramCount(pCount), annotationName(name), convention(cc), fork(fork_) {
        }

        bool operator==(const Annotation &a1) const {
            return moduleId == a1.moduleId && pc == a1.pc && paramCount == a1.paramCount &&
                   annotationName == a1.annotationName && convention == a1.convention;
        }
    };

    typedef std::vector<Annotation> Annotations;
    Annotations m_annotations;

    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    FunctionMonitor *m_functionMonitor;
    KeyValueStore *m_kvs;

    bool registerAnnotation(const Annotation &annotation);
    void hookAnnotation(S2EExecutionState *state, const ModuleDescriptor &module, const Annotation &annotation);
    void invokeAnnotation(S2EExecutionState *state, const Annotation &entry, bool isCall);
    void forkAnnotation(S2EExecutionState *state, const Annotation &entry);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);

    void onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns, const Annotation &entry);
    void onFunctionRet(S2EExecutionState *state, const Annotation &entry);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaFunctionAnnotation_H
