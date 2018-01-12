/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2013 Dependable Systems Lab, EPFL
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

#ifndef S2E_GuestCodePatching

#define S2E_GuestCodePatching

#include "s2e.h"

typedef struct _S2E_HOOK
{
    UINT64 ModuleName;
    UINT64 FunctionName;
    UINT64 Address;
} S2E_HOOK;

typedef struct _S2E_DIRECT_HOOK
{
    UINT64 HookedFunctionPc;
    UINT64 HookPc;
} S2E_DIRECT_HOOK;

typedef struct _S2E_HOOK_MODULE_IMPORTS
{
    UINT64 ModuleName;
    UINT32 Outcome;
} S2E_HOOK_MODULE_IMPORTS;

typedef struct _S2E_HOOK_ENTRYPOINT
{
    UINT64 Name;

    /* The address of the entrypoint */
    UINT64 Address;

    /**
     * The address of the hook (if available) that
     * the plugin will invoke instead of the real
     * entry point
     */
    UINT64 Hook;

    /**
     * Group which this entry point belongs to.
     * Useful to be able to deregister all entry points at once.
     */
    UINT64 Handle;

    /**
     * Address of a function to hook that is external to the module.
     * When non-null, Address must be any function belonging to
     * the calling driver.
     */
    UINT64 ExternalFunctionAddress;
} S2E_HOOK_ENTRYPOINT;

typedef enum _S2E_HOOK_PLUGIN_COMMANDS
{
    REGISTER_KERNEL_FUNCTION,
    HOOK_MODULE_IMPORTS,
    REGISTER_ENTRY_POINT,
    DEREGISTER_ENTRY_POINT,
    REGISTER_RETURN_HOOK,

    /**
     * Direct hooks will cause a simple jump to the
     * hook function. Unlike other types of hooks,
     * the address of the hooked function will not be
     * passed to the hook. It is up to determine
     * the address of the original function, if needed.
     */
    REGISTER_DIRECT_KERNEL_HOOK,
    DEREGISTER_DIRECT_KERNEL_HOOK
} S2E_HOOK_PLUGIN_COMMANDS;

#pragma warning(push)
#pragma warning(disable:4201) //Nameless union
typedef struct _S2E_HOOK_PLUGIN_COMMAND
{
    S2E_HOOK_PLUGIN_COMMANDS Command;

    union
    {
        S2E_HOOK KernelFunction;
        S2E_HOOK_MODULE_IMPORTS PatchModule;
        S2E_HOOK_ENTRYPOINT EntryPoint;
        S2E_DIRECT_HOOK DirectHook;
        UINT64 ReturnHook;
    };
} S2E_HOOK_PLUGIN_COMMAND;
#pragma warning(pop)

static inline VOID GuestCodePatchingRegisterHook(const S2E_HOOK *Hook)
{
    S2E_HOOK_PLUGIN_COMMAND Command;
    Command.Command = REGISTER_KERNEL_FUNCTION;
    Command.KernelFunction = *Hook;
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

static inline VOID RegisterHooks(const S2E_HOOK *Hooks)
{
    while (Hooks->Address) {
        GuestCodePatchingRegisterHook(Hooks);
        ++Hooks;
    }
}

static inline VOID S2ERegisterDriverEntryPoint(UINT64 Handle, PCSTR Name, PVOID Address, PVOID Hook)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    S2EMessageFmt("Registering entry point %s Handle=%p Address=%p Hook=%p\n",
                  Name, (UINT_PTR)Handle, Address, Hook);

    Command.Command = REGISTER_ENTRY_POINT;
    Command.EntryPoint.Address = (UINT_PTR)Address;
    Command.EntryPoint.Hook = (UINT_PTR)Hook;
    Command.EntryPoint.Name = (UINT_PTR)Name;
    Command.EntryPoint.Handle = (UINT_PTR)Handle;
    Command.EntryPoint.ExternalFunctionAddress = 0;

    __s2e_touch_string(Name);
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

static inline VOID S2ERegisterExternalFunctionHook(UINT64 Handle, PCSTR Name, PVOID ModuleAddress, PVOID Address, PVOID Hook)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    S2EMessageFmt("Registering hook for external function %s Handle=%p Address=%p Hook=%p\n",
                  Name, (UINT_PTR)Handle, Address, Hook);

    if (!ModuleAddress) {
        S2EMessageFmt("No module address specified\n");
        return;
    }

    Command.Command = REGISTER_ENTRY_POINT;
    Command.EntryPoint.Address = (UINT_PTR)ModuleAddress;
    Command.EntryPoint.Hook = (UINT_PTR)Hook;
    Command.EntryPoint.Name = (UINT_PTR)Name;
    Command.EntryPoint.Handle = (UINT_PTR)Handle;
    Command.EntryPoint.ExternalFunctionAddress = (UINT_PTR)Address;

    __s2e_touch_string(Name);
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

static inline VOID S2EDeregisterDriverEntryPoint(UINT64 Handle, PVOID Address)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    S2EMessageFmt("Deregistering entry point Handle=%p Address=%p\n",
                  (UINT_PTR)Handle, Address);

    Command.Command = DEREGISTER_ENTRY_POINT;
    Command.EntryPoint.Address = (UINT_PTR)Address;
    Command.EntryPoint.Handle = (UINT_PTR)Handle;

    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

static inline INT RegisterModule(PCSTR ModuleName)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    Command.Command = HOOK_MODULE_IMPORTS;
    Command.PatchModule.ModuleName = (UINT_PTR)ModuleName;
    Command.PatchModule.Outcome = 0;

    __s2e_touch_string(ModuleName);
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));

    return Command.PatchModule.Outcome;
}

static inline VOID GuestCodePatchingRegisterDirectKernelHook(UINT64 HookedFunction, UINT64 Hook)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    Command.Command = REGISTER_DIRECT_KERNEL_HOOK;
    Command.DirectHook.HookedFunctionPc = HookedFunction;
    Command.DirectHook.HookPc = Hook;
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

static inline VOID GuestCodePatchingDeregisterDirectKernelHook(UINT64 HookedFunction)
{
    S2E_HOOK_PLUGIN_COMMAND Command;

    Command.Command = DEREGISTER_DIRECT_KERNEL_HOOK;
    Command.DirectHook.HookedFunctionPc = HookedFunction;
    Command.DirectHook.HookPc = 0;
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}

#if defined(_AMD64_)
static inline VOID S2ERegisterReturnHook64(VOID)
{
    S2E_HOOK_PLUGIN_COMMAND Command;
    Command.Command = REGISTER_RETURN_HOOK;
    Command.ReturnHook = (UINT_PTR)S2EReturnHook64;
    S2EInvokePlugin("GuestCodePatching", &Command, sizeof(Command));
}
#endif

#endif
