/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#ifndef SE_CPU_CONFIG_H
#define SE_CPU_CONFIG_H

#include <cpu/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SYMBEX

/** Enables symbolic execution TLB to speed-up concrete memory accesses */
#define SE_ENABLE_TLB

/** This defines the size of each MemoryObject that represents physical RAM.
    Larger values save some memory, smaller (exponentially) decrease solving
    time for constraints with symbolic addresses */

#ifdef SE_ENABLE_TLB
// XXX: Use TARGET_PAGE_BITS somehow...
#define SE_RAM_OBJECT_BITS 12
#else
/* Do not touch this */
#define SE_RAM_OBJECT_BITS TARGET_PAGE_BITS
#endif

/** Force page sizes to be the native size. A symbex engine could perform dynamic page splitting
    in case of symbolic addresses, so there is no need to tweak this value anymore. */
#if SE_RAM_OBJECT_BITS != 12 || !defined(SE_ENABLE_TLB)
#error Incorrect TLB configuration
#endif

#define SE_RAM_OBJECT_SIZE (1 << SE_RAM_OBJECT_BITS)
#define SE_RAM_OBJECT_MASK (~(SE_RAM_OBJECT_SIZE - 1))

/** Whether to compile softmmu with memory tracing enabled. */
/** Can be disabled for debugging purposes. */
#if !defined(STATIC_TRANSLATOR)
#define SE_ENABLE_MEM_TRACING
#define TCG_ENABLE_MEM_TRACING
#endif

#ifdef CONFIG_SYMBEX_MP
#define SE_ENABLE_PHYSRAM_TLB
#endif

//#define SE_ENABLE_FAST_DIRTYMASK

/**
 * Use retranslation when recomputing the precise pc for
 * blocks that are not instrumented. Reduces the use of
 * expensive metadata.
 */
#define SE_ENABLE_RETRANSLATION

/** When enabled, the program counter is explicitely updated
 * between each guest instruction and compared to the
 * program counter recovered by cpu_restore_state. */
//#define ENABLE_PRECISE_EXCEPTION_DEBUGGING
//#define ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE

#endif // CONFIG_SYMBEX

#ifdef __cplusplus
}
#endif

#endif // SE_CPU_CONFIG_H
