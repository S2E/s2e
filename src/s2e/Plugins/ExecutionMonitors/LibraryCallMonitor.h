///
/// Copyright (C) 2011-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_LibraryCallMonitor_H
#define S2E_PLUGINS_LibraryCallMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {

class ModuleMap;
class OSMonitor;
class ProcessExecutionDetector;
class Vmi;

///
/// \brief Monitors external library function calls.
///
/// This plugin can be used to determine what external library calls a particular module makes at run time (including
/// both libraries and process main binaries). The modules to monitor are those defined in the
/// \code ProcessExecutionDetector plugin's config.
///
/// The plugin works as follows:
///   \li All indirect calls are monitored. Library calls are always made indirectly (via either the PLT in ELF
///       binaries or the IAT in PE binaries)
///   \li When an indirect call is made, we look up the module that contains the call target address
///   \li Once we find that module, we can search its export table to find an entry that matches the call target
///       address. If a match is found, report it
///
/// Note that this approach does not use the callee module's import table. This means that library calls that are not
/// listed in the import table are still monitored. This is beneficial for malware analysis, where the import table
/// is often destroyed and library calls are made "indirectly" (e.g. via \code LoadLibrary and \code GetProcAddress).
///
/// <h2>Configuration Options</h2>
///
///   \li \code monitorAllModules: enable if you want to track library calls from \a all modules used by the module
///       specified in the \code ProcessExecutionDetector plugin config.
///   \li \code monitorIndirectJumps: enable if you want to track library calls that are made via jumps, not just via
///       calls. For example, malware might do this as an obfuscation technique.
///
class LibraryCallMonitor : public Plugin {
    S2E_PLUGIN

public:
    LibraryCallMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    /// Emitted on an external library function call.
    sigc::signal<void, S2EExecutionState *, /* The current execution state */
                 const ModuleDescriptor &,  /* The module that is being called */
                 uint64_t>                  /* The called function's address */
        onLibraryCall;

private:
    ModuleMap *m_map;
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_procDetector;
    Vmi *m_vmi;

    bool m_monitorAllModules;
    bool m_monitorIndirectJumps;

    void logLibraryCall(S2EExecutionState *state, const std::string &callerMod, uint64_t pc, unsigned sourceType,
                        const std::string &calleeMod, const std::string &function) const;

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);
    void onIndirectCallOrJump(S2EExecutionState *state, uint64_t pc, unsigned sourceType);
};

} // namespace plugins
} // namespace s2e

#endif
