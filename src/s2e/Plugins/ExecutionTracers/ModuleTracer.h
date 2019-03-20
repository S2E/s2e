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

    ExecutionTracer *m_tracer;

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
}
}
#endif
