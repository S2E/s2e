///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_EXECTRACER_H
#define S2E_PLUGINS_EXECTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <boost/circular_buffer.hpp>

#include <stdio.h>

#include "TraceEntries.h"

namespace s2e {
namespace plugins {

class OSMonitor;

// Maps a module descriptor to an id, for compression purposes
typedef std::multimap<ModuleDescriptor, uint16_t, ModuleDescriptor::ModuleByLoadBase> ExecTracerModules;

/**
 *  This plugin manages the binary execution trace file.
 *  It makes sure that all the writes properly go through it.
 *  Each write is encapsulated in an ExecutionTraceItem before being
 *  written to the file.
 */
class ExecutionTracer : public Plugin {
    S2E_PLUGIN

    std::string m_fileName;
    FILE *m_LogFile;
    uint32_t m_CurrentIndex;
    OSMonitor *m_Monitor;
    ExecTracerModules m_Modules;

    uint16_t getCompressedId(const ModuleDescriptor *desc);

    void onTimer();
    void createNewTraceFile(bool append);

public:
    ExecutionTracer(S2E *s2e) : Plugin(s2e) {
    }
    ~ExecutionTracer();
    void initialize();

    uint32_t writeData(S2EExecutionState *state, void *data, unsigned size, ExecTraceEntryType type);

    void flush();
    bool flushCircularBufferToFile();

private:
    typedef boost::circular_buffer<ExecutionTraceAllItems> PartialTrace;
    PartialTrace m_circularBuffer;
    bool m_useCircularBuffer;

    void appendToCircularBuffer(const ExecutionTraceItemHeader *header, const void *data, unsigned size);
    bool appendToTraceFile(const ExecutionTraceItemHeader *header, const void *data, unsigned size);

    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);

    void onProcessFork(bool preFork, bool isChild, unsigned parentProcId);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
