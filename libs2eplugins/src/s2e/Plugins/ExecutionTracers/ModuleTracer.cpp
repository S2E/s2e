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

#include <iostream>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <TraceEntries.pb.h>

#include "ModuleTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleTracer, "Module load/unload tracer plugin",
                  "ModuleTracer"
                  "ExecutionTracer",
                  "OSMonitor");

ModuleTracer::ModuleTracer(S2E *s2e) : EventTracer(s2e) {
}

ModuleTracer::~ModuleTracer() {
}

void ModuleTracer::initialize() {
    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    OSMonitor *monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    // These module events must come first/last in the trace for it to be parsed properly.
    monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleTracer::moduleLoadListener),
                                  sigc::signal_base::HIGHEST_PRIORITY);
    monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleTracer::moduleUnloadListener),
                                    sigc::signal_base::LOWEST_PRIORITY);
    monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ModuleTracer::processUnloadListener),
                                     sigc::signal_base::LOWEST_PRIORITY);
}

bool ModuleTracer::initSection(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId) {
    return true;
}

bool ModuleTracer::moduleToProtobuf(const ModuleDescriptor &module, std::string &data) {
    s2e_trace::PbTraceModuleLoadUnload te;
    te.set_name(module.Name.c_str());
    te.set_path(module.Path.c_str());
    te.set_pid(module.Pid);
    te.set_address_space(module.AddressSpace);

    for (const auto &section : module.Sections) {
        auto s = te.add_sections();
        s->set_name(section.name.c_str());
        s->set_runtime_load_base(section.runtimeLoadBase);
        s->set_native_load_base(section.nativeLoadBase);
        s->set_size(section.size);
        s->set_readable(section.readable);
        s->set_writable(section.writable);
        s->set_executable(section.executable);
    }

    return te.AppendToString(&data);
}

void ModuleTracer::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {

    std::string data;
    if (moduleToProtobuf(module, data)) {
        m_tracer->writeData(state, data.c_str(), data.size(), s2e_trace::TRACE_MOD_LOAD);
    }
}

void ModuleTracer::moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    std::string data;
    if (moduleToProtobuf(module, data)) {
        m_tracer->writeData(state, data.c_str(), data.size(), s2e_trace::TRACE_MOD_UNLOAD);
    }
}

void ModuleTracer::processUnloadListener(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                         uint64_t returnCode) {
    s2e_trace::PbTraceProcessUnload item;
    item.set_return_code(returnCode);
    m_tracer->writeData(state, item, s2e_trace::TRACE_PROC_UNLOAD);
}
} // namespace plugins
} // namespace s2e
