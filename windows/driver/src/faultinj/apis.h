///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include <s2e/GuestCodeHooking.h>

extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelExHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelMmHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelPsHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelObHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelRegHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelFltHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelFsHooks[];
extern const S2E_GUEST_HOOK_LIBRARY_FCN g_kernelIoHooks[];
