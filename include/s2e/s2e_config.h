///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
