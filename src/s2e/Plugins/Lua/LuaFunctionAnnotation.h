///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LuaFunctionAnnotation_H
#define S2E_PLUGINS_LuaFunctionAnnotation_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor2.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class FunctionMonitor2;
class FunctionMonitorState;
class KeyValueStore;
class ModuleExecutionDetector;
class OSMonitor;
class ModuleMap;
class ProcessExecutionDetector;

class LuaFunctionAnnotation : public Plugin {
    S2E_PLUGIN

public:
    LuaFunctionAnnotation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    struct Annotation {
        enum CallingConvention { STDCALL, CDECL, MAX_CONV };

        const std::string moduleName;
        const uint64_t pc;
        const unsigned paramCount;
        const std::string annotationName;
        const CallingConvention convention;
        const bool fork;

        Annotation(const std::string &moduleName, uint64_t pc_, unsigned pCount, const std::string &name,
                   CallingConvention cc, bool fork_)
            : moduleName(moduleName), pc(pc_), paramCount(pCount), annotationName(name), convention(cc), fork(fork_) {
        }

        bool operator==(const Annotation &a1) const {
            return moduleName == a1.moduleName && pc == a1.pc && paramCount == a1.paramCount &&
                   annotationName == a1.annotationName && convention == a1.convention;
        }
    };

    using AnnotationPtr = std::shared_ptr<Annotation>;

    typedef std::vector<AnnotationPtr> Annotations;
    Annotations m_annotations;

    FunctionMonitor2 *m_functionMonitor;
    KeyValueStore *m_kvs;

    bool registerAnnotation(const Annotation &annotation);
    void invokeAnnotation(S2EExecutionState *state, const Annotation &entry, bool isCall);
    void forkAnnotation(S2EExecutionState *state, const Annotation &entry);

    void onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
                uint64_t callerPc, uint64_t calleePc, const FunctionMonitor2::ReturnSignalPtr &returnSignal);

    void onRet(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
               uint64_t returnSite, AnnotationPtr annotation);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaFunctionAnnotation_H
