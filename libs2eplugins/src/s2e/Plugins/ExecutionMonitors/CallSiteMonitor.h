///
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_PLUGINS_CallSiteMonitor_H
#define S2E_PLUGINS_CallSiteMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <unordered_map>

namespace s2e {
namespace plugins {

class OSMonitor;

///
/// \brief The CallSiteMonitor class instruments calls, indirect calls,
/// and indirect jumps in order to track their target.

/// This plugin can be used to discover function entry points dynamically
/// (called directly or indirectly) as well as analyze jump tables (indirect
/// jumps).
///
/// Client plugins can request a json file with a dump of all call sites.
/// The json file is structured as follows:
///
/// \code{.json}
/// {"module1": [[source, target, flags], ...], "module2":[[...], ...]}
/// \endcode
///
/// <tt>flags</tt> can be 0 (direct call), 1 (indirect call), 2 (indirect jump).
/// Bit 2-3 indicate that the source and/or the target is a JIT region.
///
///
/// TODO:
///
///   \li api to retrieve the information in various forms (e.g., signals)
///   \li per-path call site information
///
/// <h2>Configuration Options:</h2>
///
///   \li <tt><b>dumpInfoInterval</b></tt>: when set to n > 0,
///       the plugin will dump call site information every n seconds
///       to a json file in the S2E output folder.
///
class CallSiteMonitor : public Plugin {
    S2E_PLUGIN
public:
    CallSiteMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    /// Generate a json file with call site information and return the file name
    /// \return path to the generated file
    std::string generateJsonFile();

    /// Stores call site information in a json file specified in \p path
    /// \param path the path of the json file
    void generateJsonFile(const std::string &path);

    /// Stores call site information in a json string
    /// \param callSiteInfo the json string output
    void generateJson(std::stringstream &callSiteInfo);

private:
    // Do not modify the ordering, the values
    // are used in json output.
    enum CallSiteType {
        // Bits 0-1 indicate the type of call site
        CALL = 0,
        INDIRECT_CALL = 1,
        INDIRECT_JUMP = 2,

        // Bit 2-3 indicate whether the source and/or dest
        // are outside any text section
        JIT_SOURCE = 4,
        JIT_TARGET = 8
    };

    struct CallSite {
        CallSiteType type;
        uint64_t source;
        uint64_t target;

        CallSite() : type(CALL), source(0), target(0) {
        }

        bool operator()(const CallSite &a, const CallSite &b) const {
            if (a.source != b.source) {
                return a.source < b.source;
            }
            if (a.target != b.target) {
                return a.target < b.target;
            }
            return a.type < b.type;
        }
    };

    // Use an immutable set to share as much information between the states.
    // This also avoids costly copying when forking.
    typedef std::set<CallSite, CallSite> CallSites;
    typedef std::unordered_map<std::string, CallSites> PidCallSites;

    PidCallSites m_callSites;

    ProcessExecutionDetector *m_procDetector;
    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;

    unsigned m_dumpPeriod;
    unsigned m_lastDumpedTime;

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);

    void onInstruction(S2EExecutionState *state, uint64_t source_pc, unsigned source_type);
    void onTimer();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CallSiteMonitor_H
