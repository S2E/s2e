///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _WINDOWS_INTERCEPTOR_H_

#define _WINDOWS_INTERCEPTOR_H_

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <vmi/ntddk.h>

namespace vmi {
class PEFile;
}

namespace s2e {
namespace plugins {

/**
 * Base class for all Windows monitoring plugins.
 * Allows to abstract away different Windows versions.
 */
class WindowsInterceptor : public OSMonitor {
private:
    template <typename T> static void getContext(S2EExecutionState *state, T &context);

public:
    WindowsInterceptor(S2E *s2e) : OSMonitor(s2e) {
    }

    static void getContext32(S2EExecutionState *state, vmi::windows::CONTEXT32 &context);
    static void getContext64(S2EExecutionState *state, vmi::windows::CONTEXT64 &context);

    vmi::PEFile *getPEFile(S2EExecutionState *s, const ModuleDescriptor &desc);

    virtual bool CheckPanic(uint64_t eip) const = 0;
    virtual uint64_t getKdDebuggerDataBlock() const = 0;
    virtual uint64_t getKprcbAddress() const = 0;
    virtual bool isCheckedBuild() const = 0;
    virtual const vmi::windows::DBGKD_GET_VERSION64 &getVersionBlock() const = 0;

    /**
     * Address of the function in the guest kernel that will handle the crash for us.
     * Useful to perform complex OS-specific stuff (e.g, generating crash dumps).
     */
    virtual uint64_t getCrashRedirectionRoutine() const {
        /* No redirection by default */
        return 0;
    }

    template <typename T> static bool readConcreteParameter(S2EExecutionState *s, unsigned param, T *val) {
        return s->readMemoryConcrete(s->getSp() + (param + 1) * sizeof(T), val, sizeof(*val));
    }
};
}
}

#endif
