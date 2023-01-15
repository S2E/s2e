///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

    sigc::signal<void, S2EExecutionState *> onProcessOrThreadSwitch;

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

    /// Cache kernel address for quicker translation
    uint64_t m_cachedKernelStart;

    OSMonitor(S2E *s2e) : Plugin(s2e), m_initialized(false), m_cachedKernelStart(-1) {
    }

    void completeInitialization(S2EExecutionState *state) {
        if (!m_initialized) {
            m_initialized = true;
            m_cachedKernelStart = getKernelStart();
            onMonitorLoad.emit(state);
        }
    }

public:
    virtual uint64_t getKernelStart() const = 0;

    /// Returns \c true if the given program counter is located within the kernel space
    inline bool isKernelAddress(uint64_t pc) const {
        return pc >= getKernelStart();
    }

    ///
    /// \brief Return the pid of the process currently active in the given state.
    ///
    /// \param state the execution state
    /// \return the program id
    ///
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
        return s->mem()->read(s->regs()->getSp() + (param + 1) * sizeof(T), val, sizeof(*val));
    }

    ///
    /// \brief translatePid
    ///
    /// Windows and Linux OSes typically split the address space in two: kernel and user.
    /// The kernel is shared between all address spaces and processes. Therefore, any module
    /// loaded in kernel space is "visible" to all processes. By convention, S2E plugins
    /// assign a pid 0 to such modules. When a plugin wants to get a module loaded at a given
    /// (pid, pc), we need to set the pid to 0 if pc falls in the kernel area. It is the
    /// responsibility of the OS monitor plugins to set the pid to 0 when they emit an
    /// onModuleLoad signal for a module that is loaded in kernel space.
    ///
    /// \param pid the original process id
    /// \param pc the program counter to query
    /// \return 0 if pc is in kernel space, pid otherwise
    ///
    uint64_t translatePid(uint64_t pid, uint64_t pc) const {
        assert(m_initialized);
        if (pc >= m_cachedKernelStart) {
            return 0;
        } else {
            return pid;
        }
    }
};

} // namespace plugins
} // namespace s2e

#endif
