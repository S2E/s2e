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

///
/// \brief Base class for plugins that export OS events
///
/// This class provides a generic way for client plugins to react
/// to OS events, such as module and process loads/unloads, thread
/// and process creation, etc. It also provides an interface to
/// get the current state of the OS (currently running pid/tid,
/// stack, etc.)
///
/// If you wish to add support for a new OS, implement this interface.
///
///  Note: several events use ModuleDescriptor as a parameter.
///  The passed reference is valid only during the call. Do not store pointers
///  to such objects, but make a copy instead.
///
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

    ///
    /// \brief Triggered when the OSMonitor plugin is ready for use.
    ///
    /// Before this signal is triggered, it may be unsafe to call certain
    /// OS monitor functions (e.g., getPid() may crash or not work as expected).
    ///
    /// In general, OS monitors rely on a guest kernel driver in order
    /// to monitor for events. Before this driver is loaded, most of the interface
    /// may be unavailable.
    ///
    sigc::signal<void, S2EExecutionState *> onMonitorLoad;

protected:
    /// Indicates whether the monitor is ready to be called by other plugins
    bool m_initialized;

    OSMonitor(S2E *s2e) : Plugin(s2e), m_initialized(false) {
    }

public:
    virtual uint64_t getKernelStart() const = 0;

    /// Returns \c true if the given program counter is located within the kernel space
    inline bool isKernelAddress(uint64_t pc) const {
        return pc >= getKernelStart();
    }

    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc) = 0;

    virtual uint64_t getPageDir(S2EExecutionState *s, uint64_t pc) {
        return getAddressSpace(s, pc);
    }

    ///
    /// \brief Return the pid of the process currently active in the given state.
    ///
    /// Note: OSes may split the address space into two, the upper part being
    /// mapped across every process. Depending on the OS monitor, this function
    /// may return 0 if the program counter points to kernel space. This is to
    /// simplify client plugins (e.g., module map) and avoid making them duplicate every
    /// kernel module in all address space.
    ///
    /// \param state the execution state
    /// \param pc the program counter (user/kernel space)
    /// \return the program id
    ///
    virtual uint64_t getPid(S2EExecutionState *state, uint64_t pc) = 0;

    uint64_t getPid(S2EExecutionState *state) {
        return getPid(state, state->regs()->getPc());
    }

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
        return s->mem()->read(s->regs()->getSp() + (param + 1) * sizeof(T), val, sizeof(*val));
    }
};

} // namespace plugins
} // namespace s2e

#endif
