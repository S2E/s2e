///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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
