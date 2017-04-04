///
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LuaFunctionAnnotation_H
#define S2E_PLUGINS_LuaFunctionAnnotation_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/Support/KeyValueStore.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class OSMonitor;

enum S2E_LUA_FCN_ANN_COMMANDS { REGISTER_ANNOTATION } __attribute__((aligned(8)));

struct S2E_LUA_FCN_ANN_REGISTER {
    uint64_t Pc;
    uint64_t ParamCount;
    uint64_t AnnotationNameStr;
    uint64_t CallingConvention;
} __attribute__((aligned(8)));

struct S2E_LUA_FCN_ANN_COMMAND {
    S2E_LUA_FCN_ANN_COMMANDS Command;
    union {
        uint64_t Result;
        S2E_LUA_FCN_ANN_REGISTER RegisterAnnotation;
    };
} __attribute__((aligned(8)));

class LuaFunctionAnnotation : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    LuaFunctionAnnotation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    enum CallingConvention { STDCALL, CDECL, MAX_CONV };

    struct Annotation {
        std::string moduleId;
        uint64_t pc;
        unsigned paramCount;
        std::string annotationName;
        CallingConvention convention;
        bool fork;

        bool operator==(const Annotation &a1) const {
            return moduleId == a1.moduleId && pc == a1.pc && paramCount == a1.paramCount &&
                   annotationName == a1.annotationName && convention == a1.convention;
        }
    };

    typedef std::vector<Annotation *> Annotations;
    Annotations m_annotations;

    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    FunctionMonitor *m_functionMonitor;
    KeyValueStore *m_kvs;

    bool registerAnnotation(const Annotation &annotation);
    void hookAnnotation(S2EExecutionState *state, const ModuleDescriptor &module, const Annotation *annotation);
    void invokeAnnotation(S2EExecutionState *state, const Annotation &entry, bool isCall);
    void forkAnnotation(S2EExecutionState *state, const Annotation &entry);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);

    void onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns, const Annotation *entry);

    void onFunctionRet(S2EExecutionState *state, const Annotation *entry);
};

class LuaFunctionAnnotationState : public PluginState {
private:
    bool m_child;

public:
    LuaFunctionAnnotationState();
    virtual ~LuaFunctionAnnotationState();
    virtual LuaFunctionAnnotationState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class LuaFunctionAnnotation;

    bool isChild() const {
        return m_child;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaFunctionAnnotation_H
