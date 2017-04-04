///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_EVENTTRACER_H
#define S2E_PLUGINS_EVENTTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include "ExecutionTracer.h"

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <map>
#include <stdio.h>
#include <string>

namespace s2e {
namespace plugins {

struct TracerConfigEntry {
    std::string moduleId;
    bool traceAll;

    TracerConfigEntry() {
        traceAll = false;
    }

    virtual ~TracerConfigEntry() {
    }
};

typedef TracerConfigEntry *(*TracerConfigEntryFactory)();

// Maps a module name to a configuration entry
typedef std::map<std::string, TracerConfigEntry *> EventTracerCfgMap;

/**
 *  Base class for all types of tracers.
 *  Handles the basic boilerplate (e.g., common config options).
 */
class EventTracer : public Plugin {

protected:
    ModuleExecutionDetector *m_Detector;
    ExecutionTracer *m_Tracer;
    EventTracerCfgMap m_Modules;
    bool m_TraceAll;
    TracerConfigEntry *m_TraceAllCfg;
    bool m_Debug;

    EventTracer(S2E *s2e);
    virtual ~EventTracer();

    void initialize();

private:
    bool initBaseParameters(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId);

    bool registerConfigEntry(TracerConfigEntry *cfgEntry);

protected:
    bool initSections(TracerConfigEntryFactory cfgFactory);

    virtual bool initSection(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId) = 0;
};
}
}

#endif
