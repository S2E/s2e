/// Copyright (C) 2003  Fabrice Bellard
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

#ifndef __LIBCPU_TYPES_H__

#define __LIBCPU_TYPES_H__

#include <inttypes.h>

#include <cpu/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TARGET_X86_64
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif

/* HOST_LONG_BITS is the size of a native pointer in bits. */
#if UINTPTR_MAX == UINT32_MAX
#define HOST_LONG_BITS 32
#elif UINTPTR_MAX == UINT64_MAX
#define HOST_LONG_BITS 64
#else
#error Unknown pointer size
#endif

#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)

typedef int16_t target_short __attribute__((aligned(TARGET_SHORT_ALIGNMENT)));
typedef uint16_t target_ushort __attribute__((aligned(TARGET_SHORT_ALIGNMENT)));
typedef int32_t target_int __attribute__((aligned(TARGET_INT_ALIGNMENT)));
typedef uint32_t target_uint __attribute__((aligned(TARGET_INT_ALIGNMENT)));
typedef int64_t target_llong __attribute__((aligned(TARGET_LLONG_ALIGNMENT)));
typedef uint64_t target_ullong __attribute__((aligned(TARGET_LLONG_ALIGNMENT)));
/* target_ulong is the type of a virtual address */
#if TARGET_LONG_SIZE == 4
typedef int32_t target_long __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
typedef uint32_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#define TARGET_FMT_lx "%08x"
#define TARGET_FMT_ld "%d"
#define TARGET_FMT_lu "%u"
#elif TARGET_LONG_SIZE == 8
typedef int64_t target_long __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
typedef uint64_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#define TARGET_FMT_lx "%016" PRIx64
#define TARGET_FMT_ld "%" PRId64
#define TARGET_FMT_lu "%" PRIu64
#else
#error TARGET_LONG_SIZE undefined
#endif

#ifdef TARGET_PHYS_ADDR_BITS
/* target_phys_addr_t is the type of a physical address (its size can
   be different from 'target_ulong').  */

#if TARGET_PHYS_ADDR_BITS == 32
typedef uint32_t target_phys_addr_t;
#define TARGET_PHYS_ADDR_MAX UINT32_MAX
#define TARGET_FMT_plx "%08x"
#elif TARGET_PHYS_ADDR_BITS == 64
typedef uint64_t target_phys_addr_t;
#define TARGET_PHYS_ADDR_MAX UINT64_MAX
#define TARGET_FMT_plx "%016" PRIx64
#endif
#endif

typedef uintptr_t ram_addr_t;

#ifdef __cplusplus
}
#endif

#endif
