///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_MODULETRACER_H
#define S2E_PLUGINS_MODULETRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include "EventTracer.h"
#include "ExecutionTracer.h"

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

    static bool moduleToProtobuf(const ModuleDescriptor &module, std::string &data);

    void moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module);

    void moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &desc);

    void processUnloadListener(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
};
} // namespace plugins
} // namespace s2e
#endif
