///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#ifndef S2E_CONFIG_H
#define S2E_CONFIG_H

/** How many S2E instances we want to handle.
    Plugins can use this constant to allocate blocks of shared memory whose size
    depends on the maximum number of processes (e.g., bitmaps) */
#define S2E_MAX_PROCESSES 48

#define S2E_USE_FAST_SIGNALS

#define S2E_MEMCACHE_SUPERPAGE_BITS 20

#define S2E_RAM_SUBOBJECT_BITS 7
#define S2E_RAM_SUBOBJECT_SIZE (1 << S2E_RAM_SUBOBJECT_BITS)

#include <cpu/se_libcpu_config.h>

#endif // S2E_CONFIG_H
