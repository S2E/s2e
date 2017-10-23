///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ModuleTracer.h"
#include "TraceEntries.h"

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <llvm/Support/TimeValue.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ModuleTracer, "Module load/unload tracer plugin", "ModuleTracer"
                                                                    "ExecutionTracer",
                  "OSMonitor");

ModuleTracer::ModuleTracer(S2E *s2e) : EventTracer(s2e) {
}

ModuleTracer::~ModuleTracer() {
}

void ModuleTracer::initialize() {
    m_Tracer = s2e()->getPlugin<ExecutionTracer>();
    assert(m_Tracer);

    OSMonitor *monitor = (OSMonitor *) s2e()->getPlugin("OSMonitor");
    assert(monitor);

    monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ModuleTracer::moduleLoadListener));

    monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ModuleTracer::moduleUnloadListener));

    monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ModuleTracer::processUnloadListener));
}

bool ModuleTracer::initSection(TracerConfigEntry *cfgEntry, const std::string &cfgKey, const std::string &entryId) {
    return true;
}

void ModuleTracer::moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module) {
    ExecutionTraceModuleLoad te;
    strncpy(te.name, module.Name.c_str(), sizeof(te.name));
    strncpy(te.path, module.Path.c_str(), sizeof(te.path));
    te.loadBase = module.LoadBase;
    te.nativeBase = module.NativeBase;
    te.size = module.Size;
    te.addressSpace = module.AddressSpace;
    te.pid = module.Pid;

    m_Tracer->writeData(state, &te, sizeof(te), TRACE_MOD_LOAD);
}

void ModuleTracer::moduleUnloadListener(S2EExecutionState *state, const ModuleDescriptor &desc) {
    ExecutionTraceModuleUnload te;
    te.loadBase = desc.LoadBase;

    m_Tracer->writeData(state, &te, sizeof(te), TRACE_MOD_UNLOAD);
}

void ModuleTracer::processUnloadListener(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                         uint64_t returnCode) {
    ExecutionTraceProcessUnload te;
    te.returnCode = returnCode;

    m_Tracer->writeData(state, &te, sizeof(te), TRACE_PROC_UNLOAD);
}
}
}
