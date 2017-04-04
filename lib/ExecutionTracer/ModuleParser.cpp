///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

//#define __STDC_CONSTANT_MACROS 1
//#define __STDC_LIMIT_MACROS 1
//#define __STDC_FORMAT_MACROS 1

#include "lib/BinaryReaders/Library.h"

#include <inttypes.h>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>

#include "ModuleParser.h"

namespace s2etools {

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

ModuleInstance::ModuleInstance(const std::string &name, uint64_t pid, uint64_t loadBase, uint64_t size,
                               uint64_t imageBase) {
    LoadBase = loadBase;
    ImageBase = imageBase;
    Size = size;
    Name = name;
    // xxx: fix this
    Pid = pid;
}

void ModuleInstance::print(std::ostream &os) const {
    os << "Instance of " << Name << " Pid=0x" << std::hex << Pid << " LoadBase=0x" << LoadBase << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

ModuleCache::ModuleCache(LogEvents *Events) {
    Events->onEachItem.connect(sigc::mem_fun(*this, &ModuleCache::onItem));

    m_events = Events;
}

void ModuleCache::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {

    if (hdr.type == s2e::plugins::TRACE_MOD_LOAD) {
        const s2e::plugins::ExecutionTraceModuleLoad &load = *(s2e::plugins::ExecutionTraceModuleLoad *) item;
        ModuleCacheState *state = static_cast<ModuleCacheState *>(m_events->getState(this, &ModuleCacheState::factory));

        if (!state->loadModule(load.name, hdr.pid, load.loadBase, load.nativeBase, load.size)) {
            // std::cout << "Could not load driver " << load.name << std::endl;
        }
    } else if (hdr.type == s2e::plugins::TRACE_MOD_UNLOAD) {
        const s2e::plugins::ExecutionTraceModuleUnload &unload = *(s2e::plugins::ExecutionTraceModuleUnload *) item;
        ModuleCacheState *state = static_cast<ModuleCacheState *>(m_events->getState(this, &ModuleCacheState::factory));

        if (!state->unloadModule(hdr.pid, unload.loadBase)) {
            // std::cout << "Could not load driver " << load.name << std::endl;
        }
    } else if (hdr.type == s2e::plugins::TRACE_PROC_UNLOAD) {
        std::cerr << "Process unloading not implemented" << std::endl;
    } else {
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

const ModuleInstance *ModuleCacheState::getInstance(uint64_t pid, uint64_t pc) const {
    pid = Library::translatePid(pid, pc);

    ModuleInstance mi("", pid, pc, 1, 0);
    ModuleInstanceSet::const_iterator it = m_Instances.find(&mi);
    if (it == m_Instances.end()) {
        return NULL;
    }

    return (*it);
}

bool ModuleCacheState::loadModule(const std::string &name, uint64_t pid, uint64_t loadBase, uint64_t imageBase,
                                  uint64_t size) {
    std::cout << "Loading module " << name << " pid=0x" << std::hex << pid << " loadBase=0x" << loadBase
              << " imageBase=0x" << imageBase << " size=0x" << size << std::endl;
    pid = Library::translatePid(pid, loadBase);

    ModuleInstance *mi = new ModuleInstance(name, pid, loadBase, size, imageBase);
    ModuleInstanceSet::iterator it = m_Instances.find(mi);
    if (it != m_Instances.end()) {
        ModuleInstance *found = *it;
        std::cout << "Warning: Module already loaded (Linux exec?)\n";
        if ((*it)->ImageBase && !mi->ImageBase) {
            mi->ImageBase = (*it)->ImageBase;
        }
        m_Instances.erase(it);
        delete found;
    }
    m_Instances.insert(mi);
    return true;
}

bool ModuleCacheState::unloadModule(uint64_t pid, uint64_t loadBase) {
    std::cout << "Unloading module pid=0x" << std::hex << pid << " loadBase=0x" << loadBase << "\n";

    pid = Library::translatePid(pid, loadBase);
    ModuleInstance mi("", pid, loadBase, 1, 0);

    // Sometimes we have duplicated items in the trace
    // assert(m_Instances.find(&mi) != m_Instances.end());

    return m_Instances.erase(&mi);
}

ItemProcessorState *ModuleCacheState::factory() {
    return new ModuleCacheState();
}

ModuleCacheState::ModuleCacheState() {
}

ModuleCacheState::~ModuleCacheState() {
}

ItemProcessorState *ModuleCacheState::clone() const {
    ModuleCacheState *ret = new ModuleCacheState();

    ModuleInstanceSet::iterator it;
    for (it = m_Instances.begin(); it != m_Instances.end(); ++it) {
        ModuleInstance *newInstance = new ModuleInstance(*(*it));
        ret->m_Instances.insert(newInstance);
    }

    return ret;
}
}
