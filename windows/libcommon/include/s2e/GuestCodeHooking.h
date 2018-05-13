/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2018 Cyberhaven
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

#pragma once

#include "s2e.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _S2E_GUEST_HOOK_PLUGIN_COMMANDS
{
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

typedef struct S2E_GUEST_HOOK_DIRECT
{
    UINT64 Pid;
    UINT64 OriginalPc;
    UINT64 HookPc;
} S2E_GUEST_HOOK_DIRECT;

typedef struct S2E_GUEST_HOOK_LIBRARY_FCN
{
    UINT64 Pid;
    UINT64 LibraryName;
    UINT64 FunctionName;
    UINT64 HookPc;
    UINT64 HookReturn64;
} S2E_GUEST_HOOK_LIBRARY_FCN;

#pragma warning(push)
#pragma warning(disable:4201) //Nameless union
typedef struct _S2E_GUEST_HOOK_PLUGIN_COMMAND
{
    S2E_GUEST_HOOK_PLUGIN_COMMANDS Command;

    union
    {
        S2E_GUEST_HOOK_DIRECT DirectHook;
        S2E_GUEST_HOOK_LIBRARY_FCN CallSiteHook;
    };
} S2E_GUEST_HOOK_PLUGIN_COMMAND;
#pragma warning(pop)

//////////////

#if defined(_AMD64_)
#define __S2EReturnHook64 S2EReturnHook64
#else
#define __S2EReturnHook64 0
#endif

#define S2E_KERNEL_FCN_HOOK(ModuleName, FunctionName, HookPc) \
{ 0, (UINT_PTR) ModuleName, (UINT_PTR) FunctionName, (UINT_PTR) HookPc, (UINT_PTR) __S2EReturnHook64  }

#define S2E_KERNEL_FCN_HOOK_END() {0, 0, 0, 0, 0}

static inline VOID GuestCodeHookingRegisterLibFcnCallHook(const S2E_GUEST_HOOK_LIBRARY_FCN *Hook)
{
    S2E_GUEST_HOOK_PLUGIN_COMMAND Cmd;
    Cmd.Command = REGISTER_CALL_SITE_HOOK;
    Cmd.CallSiteHook = *Hook;
    S2EInvokePlugin("GuestCodeHooking", &Cmd, sizeof(Cmd));
}

static inline VOID GuestCodeHookingRegisterLibFcnCallHooks(const S2E_GUEST_HOOK_LIBRARY_FCN *Hooks)
{
    while (Hooks->HookPc) {
        GuestCodeHookingRegisterLibFcnCallHook(Hooks);
        ++Hooks;
    }
}

static inline VOID GuestCodeHookingRegisterDirectHook(const S2E_GUEST_HOOK_DIRECT *Hook)
{
    S2E_GUEST_HOOK_PLUGIN_COMMAND Cmd;
    Cmd.Command = REGISTER_DIRECT_HOOK;
    Cmd.DirectHook = *Hook;
    S2EInvokePlugin("GuestCodeHooking", &Cmd, sizeof(Cmd));
}

static inline VOID GuestCodeHookingRegisterDirectHooks(const S2E_GUEST_HOOK_DIRECT *Hooks)
{
    while (Hooks->HookPc) {
        GuestCodeHookingRegisterDirectHook(Hooks);
        ++Hooks;
    }
}

static inline VOID GuestCodeHookingRegisterDirectKernelHook(UINT64 HookedFunction, UINT64 HookPc)
{
    S2E_GUEST_HOOK_DIRECT Hook;
    Hook.HookPc = HookPc;
    Hook.OriginalPc = HookedFunction;
    Hook.Pid = 0; // This is special pid for kernel space

    GuestCodeHookingRegisterDirectHook(&Hook);
}

#ifdef __cplusplus
}
#endif
