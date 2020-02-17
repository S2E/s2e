///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_PLUGINS_EXECTRACER_H
#define S2E_PLUGINS_EXECTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <stdio.h>

namespace s2e_trace {
class PbTraceItemHeader;
}

namespace s2e {
namespace plugins {

class OSMonitor;

/// This plugin manages the binary execution trace file.
/// It makes sure that all the writes properly go through it.
class ExecutionTracer : public Plugin {
    S2E_PLUGIN

private:
    std::string m_fileName;
    FILE *m_logFile;
    uint32_t m_currentIndex;
    OSMonitor *m_monitor;

    void onTimer();
    void createNewTraceFile(bool append);

    bool appendToTraceFile(const s2e_trace::PbTraceItemHeader &header, const void *data, unsigned size);

    void onStateGuidAssignment(S2EExecutionState *state, uint64_t newGuid);

    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);

    void onProcessFork(bool preFork, bool isChild, unsigned parentProcId);

    void onMonitorLoad(S2EExecutionState *state);

    void onEngineShutdown();

public:
    ExecutionTracer(S2E *s2e) : Plugin(s2e) {
    }
    ~ExecutionTracer();
    void initialize();

    template <typename T> uint32_t writeData(S2EExecutionState *state, const T &item, uint32_t type) {
        std::string data;
        if (!item.AppendToString(&data)) {
            getWarningsStream(state) << "Could not serialize protobuf data\n";
            exit(-1);
        }
        return writeData(state, data.c_str(), data.size(), type);
    }

    uint32_t writeData(S2EExecutionState *state, const void *data, unsigned size,
                       uint32_t type /* s2e_trace::PbTraceItemHeaderType */);

    void flush();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
