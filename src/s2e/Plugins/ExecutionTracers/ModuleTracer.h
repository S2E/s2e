///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MODULETRACER_H
#define S2E_PLUGINS_MODULETRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include "EventTracer.h"

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

namespace s2e {
namespace plugins {

class ModuleTracer : public EventTracer {
    S2E_PLUGIN

    ExecutionTracer *m_Tracer;

public:
    ModuleTracer(S2E *s2e);
    virtual ~ModuleTracer();
    void initialize();

protected:
    virtual bool initSection(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId);

    void moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module);

    void moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &desc);

    void processUnloadListener(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
};

class ModuleTracerState : public PluginState {
public:
    typedef std::map<ModuleDescriptor, uint32_t, ModuleDescriptor::ModuleByLoadBase> DescriptorMap;

private:
    DescriptorMap m_Modules;
    mutable const ModuleDescriptor *m_CachedDesc;
    mutable uint32_t m_CachedState;
    mutable uint32_t m_CachedTraceIndex;

public:
    bool addModule(S2EExecutionState *s, const ModuleDescriptor *m, ExecutionTracer *tracer);
    bool delModule(S2EExecutionState *s, const ModuleDescriptor *m, ExecutionTracer *tracer);
    bool delProcess(S2EExecutionState *s, uint64_t pid, ExecutionTracer *tracer);

    bool getCurrentModule(S2EExecutionState *s, ModuleDescriptor *desc, uint32_t *index) const;

    ModuleTracerState();
    virtual ~ModuleTracerState();
    virtual ModuleTracerState *clone() const;
    static PluginState *factory();

    friend class ModuleTracer;
};
}
}
#endif
