///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
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
} // namespace plugins
} // namespace s2e

#endif
