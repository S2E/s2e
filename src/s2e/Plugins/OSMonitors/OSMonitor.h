///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __MODULE_MONITOR_PLUGIN_H__

#define __MODULE_MONITOR_PLUGIN_H__

#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <vmi/ExecutableFile.h>
#include "ThreadDescriptor.h"

namespace s2e {

struct ModuleDescriptor;
struct ThreadDescriptor;

namespace plugins {

/**
 *  Base class for default OS actions.
 *  It provides an interface for loading/unloading modules and processes.
 *  If you wish to add support for a new OS, implement this interface.
 *
 *  Note: several events use ModuleDescriptor as a parameter.
 *  The passed reference is valid only during the call. Do not store pointers
 *  to such objects, but make a copy instead.
 */
class OSMonitor : public Plugin {
public:
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &> onModuleLoad;

    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &> onModuleUnload;
    sigc::signal<void, S2EExecutionState *, uint64_t /* cr3 */, uint64_t /* pid */, const std::string & /*ImageName*/>
        onProcessLoad;
    sigc::signal<void, S2EExecutionState *, uint64_t /* cr3 */, uint64_t /* pid */, uint64_t /* ReturnCode */>
        onProcessUnload;

    sigc::signal<void, S2EExecutionState *, const ThreadDescriptor &> onThreadCreate;
    sigc::signal<void, S2EExecutionState *, const ThreadDescriptor &> onThreadExit;

    /* The monitoring plugin triggers this when it is ready to be used */
    sigc::signal<void, S2EExecutionState *> onMonitorLoad;

protected:
    /// Indicates whether the monitor is ready to be called by other plugins
    bool m_initialized;

    OSMonitor(S2E *s2e) : Plugin(s2e), m_initialized(false) {
    }

public:
    virtual bool isKernelAddress(uint64_t pc) const = 0;

    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc) = 0;

    virtual uint64_t getPageDir(S2EExecutionState *s, uint64_t pc) {
        return getAddressSpace(s, pc);
    }

    virtual uint64_t getPid(S2EExecutionState *state, uint64_t pc) = 0;
    virtual uint64_t getPid(S2EExecutionState *state) = 0;
    virtual uint64_t getTid(S2EExecutionState *state) = 0;

    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size) = 0;

    bool isOnTheStack(S2EExecutionState *s, uint64_t address) {
        uint64_t base, size;
        if (!getCurrentStack(s, &base, &size)) {
            return false;
        }
        return address >= base && address < (base + size);
    }

    virtual bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) = 0;

    void dumpUserspaceMemory(S2EExecutionState *state, std::ostream &ss);

    // Indicates whether the monitor is loaded and that calling its APIs is allowed.
    // This is useful for monitors that rely on a guest kernel driver to provide
    // information to plugins. Plugins should wait that the monitor is initialized
    // before calling any APIs. This call can be used together with the onMonitorLoad signal.
    bool initialized() const {
        return m_initialized;
    }

    template <typename T> static bool readConcreteParameter(S2EExecutionState *s, unsigned param, T *val) {
        return s->readMemoryConcrete(s->getSp() + (param + 1) * sizeof(T), val, sizeof(*val));
    }
};

} // namespace plugins
} // namespace s2e

#endif
