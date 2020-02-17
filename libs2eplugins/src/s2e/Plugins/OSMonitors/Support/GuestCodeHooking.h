///
/// Copyright (C) 2018 Cyberhaven
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

#ifndef S2E_PLUGINS_GuestCodeHooking_H
#define S2E_PLUGINS_GuestCodeHooking_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/S2EExecutionState.h>

#include <unordered_set>

namespace s2e {
namespace plugins {
namespace os {

typedef enum _S2E_GUEST_HOOK_PLUGIN_COMMANDS {
    /// Direct hooks will cause a simple jump to the
    /// hook function. Unlike other types of hooks,
    /// the address of the hooked function will not be
    /// passed to the hook. It is up to the hook determine
    /// the address of the original function, if needed.
    REGISTER_DIRECT_HOOK,
    UNREGISTER_DIRECT_HOOK,

    REGISTER_CALL_SITE_HOOK,
    UNREGISTER_CALL_SITE_HOOK
} S2E_GUEST_HOOK_PLUGIN_COMMANDS;

typedef struct S2E_GUEST_HOOK_DIRECT {
    uint64_t Pid;
    uint64_t OriginalPc;
    uint64_t HookPc;
} S2E_GUEST_HOOK_DIRECT;

typedef struct S2E_GUEST_HOOK_LIBRARY_FCN {
    uint64_t Pid;
    uint64_t LibraryName;
    uint64_t FunctionName;
    uint64_t HookPc;
    uint64_t HookReturn64;
} S2E_GUEST_HOOK_LIBRARY_FCN;

struct S2E_GUEST_HOOK_LIBRARY_FCN_CPP {
    uint64_t Pid;
    std::string LibraryName;
    std::string FunctionName;
    uint64_t HookPc;
    uint64_t HookReturn64;

    bool operator<(const S2E_GUEST_HOOK_LIBRARY_FCN_CPP &b) const {
        if (Pid == b.Pid) {
            if (LibraryName == b.LibraryName) {
                return FunctionName < b.FunctionName;
            } else {
                return LibraryName < b.LibraryName;
            }
        } else {
            return Pid < b.Pid;
        }
    }
};

typedef struct _S2E_GUEST_HOOK_PLUGIN_COMMAND {
    S2E_GUEST_HOOK_PLUGIN_COMMANDS Command;
    union {
        S2E_GUEST_HOOK_DIRECT DirectHook;
        S2E_GUEST_HOOK_LIBRARY_FCN CallSiteHook;
    };
} S2E_GUEST_HOOK_PLUGIN_COMMAND;

struct HookLocation {
    uint64_t pid;

    // This can be either the address of a call site
    // or the address of the function to hook.
    uint64_t pc;

    bool operator==(const HookLocation &other) const {
        return other.pid == pid && other.pc == pc;
    }
};

struct Hook {
    /// \brief The address of the hook
    uint64_t target_pc;

    /// \brief Only for 64-bit, pointer to code that will
    /// cleanup the stack and return to the caller when the hook returns.
    /// This code cleanup shoud be "add rsp, 11 * sizeof(uint64_t); ret".
    uint64_t hook_return_64;
};

class GuestCodeHooking : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
public:
    GuestCodeHooking(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    typedef std::unordered_set<std::string> StringSet;

    typedef std::function<bool(const HookLocation &, const Hook &)> GCHPredicate;

    typedef std::unordered_map<std::string, std::set<S2E_GUEST_HOOK_LIBRARY_FCN_CPP>> AvailableFcnCallHooks;

    ModuleMap *m_map;
    Vmi *m_vmi;
    OSMonitor *m_monitor;

    ///
    /// \brief Modules whose call sites will be hooked
    ///
    StringSet m_modules;

    AvailableFcnCallHooks m_availableFcnHooks;

    void erase(S2EExecutionState *state, GCHPredicate doErase);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t targetPc);

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc, uint64_t hookAddress, bool directHook);
    void onExecuteCall(S2EExecutionState *state, uint64_t pc);

    bool parseGHLFcn(S2EExecutionState *state, const S2E_GUEST_HOOK_LIBRARY_FCN &in,
                     S2E_GUEST_HOOK_LIBRARY_FCN_CPP &out);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace os
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_GuestCodeHooking_H
