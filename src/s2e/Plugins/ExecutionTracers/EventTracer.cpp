///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "EventTracer.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <llvm/Support/TimeValue.h>

#include <iostream>
#include <sstream>

namespace s2e {
namespace plugins {

EventTracer::EventTracer(S2E *s2e) : Plugin(s2e) {
}

EventTracer::~EventTracer() {
}

void EventTracer::initialize() {
    // Check that the tracer is there
    m_Tracer = s2e()->getPlugin<ExecutionTracer>();
    assert(m_Tracer);

    m_Detector = s2e()->getPlugin<ModuleExecutionDetector>();
    assert(m_Detector);

    m_TraceAll = false;
    m_TraceAllCfg = NULL;
    m_Debug = false;
}

bool EventTracer::initSections(TracerConfigEntryFactory cfgFactory) {
    m_Debug = s2e()->getConfig()->getBool(getConfigKey() + ".enableDebug");

    std::vector<std::string> Sections;
    Sections = s2e()->getConfig()->getListKeys(getConfigKey());
    bool noErrors = true;

    foreach2 (it, Sections.begin(), Sections.end()) {
        if (*it == "enableDebug") {
            continue;
        }

        getInfoStream() << "Scanning section " << getConfigKey() << "." << *it << '\n';
        std::stringstream sk;
        sk << getConfigKey() << "." << *it;

        TracerConfigEntry *cfgEntry = cfgFactory();
        assert(cfgEntry);

        if (!initBaseParameters(cfgEntry, sk.str(), *it)) {
            noErrors = false;
        }

        if (!initSection(cfgEntry, sk.str(), *it)) {
            noErrors = false;
        }

        if (!registerConfigEntry(cfgEntry)) {
            noErrors = false;
            break;
        }
    }

    if (!noErrors) {
        getWarningsStream() << "Errors while scanning the " << getConfigKey() << " sections" << '\n';
        return false;
    }

    return true;
}

bool EventTracer::initBaseParameters(TracerConfigEntry *cfgEntry, const std::string &cfgKey,
                                     const std::string &entryId) {
    bool ok;
    cfgEntry->traceAll = s2e()->getConfig()->getBool(cfgKey + ".traceAll");

    cfgEntry->moduleId = s2e()->getConfig()->getString(cfgKey + ".moduleId", "", &ok);
    if (!ok && !cfgEntry->traceAll) {
        getWarningsStream() << "You must specify " << cfgKey << ".moduleId" << '\n';
        return false;
    }
    return true;
}

bool EventTracer::registerConfigEntry(TracerConfigEntry *cfgEntry) {
    if (cfgEntry->traceAll) {
        if (m_Modules.size() > 0) {
            getWarningsStream() << "EventTracer: There can be only one entry when tracing everything" << '\n';
            return false;
        }

        m_TraceAll = true;
        m_TraceAllCfg = cfgEntry;
        return true;
    }

    EventTracerCfgMap::iterator it = m_Modules.find(cfgEntry->moduleId);
    if (it != m_Modules.end()) {
        getWarningsStream() << "EventTracer: " << cfgEntry->moduleId << " defined multiple times" << '\n';
        return false;
    }

    m_Modules[cfgEntry->moduleId] = cfgEntry;
    return true;
}
}
}
