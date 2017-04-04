///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LIBCALLMON_H
#define S2E_PLUGINS_LIBCALLMON_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <string>
#include <tr1/unordered_map>
#include <tr1/unordered_set>

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include "FunctionMonitor.h"

namespace s2e {
namespace plugins {

class OSMonitor;

class LibraryCallMonitor : public Plugin {
    S2E_PLUGIN
public:
    typedef std::tr1::unordered_set<std::string> StringSet;
    typedef std::set<std::pair<uint64_t, uint64_t>> AddressPairs;

    LibraryCallMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    sigc::signal<void, S2EExecutionState *, FunctionMonitorState *,
                 const ModuleDescriptor & /* The module  being called */>
        onLibraryCall;

private:
    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    FunctionMonitor *m_functionMonitor;
    StringSet m_functionNames;
    AddressPairs m_alreadyCalledFunctions;

    // List of modules whose calls we want to track.
    // Empty to track all modules in the system.
    StringSet m_trackedModules;

    bool m_displayOnce;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);
};

class LibraryCallMonitorState : public PluginState {
public:
    typedef std::tr1::unordered_map<uint64_t, const char *> AddressToFunctionName;

private:
    AddressToFunctionName m_functions;

public:
    LibraryCallMonitorState();
    virtual ~LibraryCallMonitorState();
    virtual LibraryCallMonitorState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class LibraryCallMonitor;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LIBCALLMON_H
