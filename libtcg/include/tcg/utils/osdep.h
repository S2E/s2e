/// Copyright (C) 2003  Fabrice Bellard
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

#ifndef TCG_OSDEP_H
#define TCG_OSDEP_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __OpenBSD__
#include <sys/signal.h>
#include <sys/types.h>
#endif

#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef glue
#define xglue(x, y)  x##y
#define glue(x, y)   xglue(x, y)
#define stringify(s) tostring(s)
#define tostring(s)  #s
#endif

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#ifndef container_of
#define container_of(ptr, type, member)                      \
    ({                                                       \
        const typeof(((type *) 0)->member) *__mptr = (ptr);  \
        (type *) ((char *) __mptr - offsetof(type, member)); \
    })
#endif

/* Convert from a base type to a parent type, with compile time checking.  */
#ifdef __GNUC__
#define DO_UPCAST(type, field, dev)                                               \
    (__extension__({                                                              \
        char __attribute__((unused)) offset_must_be_zero[-offsetof(type, field)]; \
        container_of(dev, type, field);                                           \
    }))
#else
#define DO_UPCAST(type, field, dev) container_of(dev, type, field)
#endif

#define typeof_field(type, field) typeof(((type *) 0)->field)
#define type_check(t1, t2)        ((t1 *) 0 - (t2 *) 0)

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define QEMU_FALLTHROUGH __attribute__((fallthrough))
#define QEMU_PACKED      __attribute__((packed))

/*
 * GCC doesn't provide __has_attribute() until GCC 5, but we know all the GCC
 * versions we support have the "flatten" attribute. Clang may not have the
 * "flatten" attribute but always has __has_attribute() to check for it.
 */
#if __has_attribute(flatten) || !defined(__clang__)
#define QEMU_FLATTEN __attribute__((flatten))
#else
#define QEMU_FLATTEN
#endif

/*
 * If __attribute__((error)) is present, use it to produce an error at
 * compile time.  Otherwise, one must wait for the linker to diagnose
 * the missing symbol.
 */
#if __has_attribute(error)
#define QEMU_ERROR(X) __attribute__((error(X)))
#else
#define QEMU_ERROR(X)
#endif

#ifndef NORETURN
#define NORETURN __attribute__((noreturn))
#endif

/**
 * qemu_build_not_reached()
 *
 * The compiler, during optimization, is expected to prove that a call
 * to this function cannot be reached and remove it.  If the compiler
 * supports QEMU_ERROR, this will be reported at compile time; otherwise
 * this will be reported at link time due to the missing symbol.
 */
NORETURN extern void QEMU_ERROR("code path is reachable") qemu_build_not_reached_always(void);
#if defined(__OPTIMIZE__) && !defined(__NO_INLINE__)
#define qemu_build_not_reached() qemu_build_not_reached_always()
#else
#define qemu_build_not_reached()        \
    {                                   \
        fprintf(stderr, "not reached"); \
        abort();                        \
    }
#endif

/**
 * qemu_build_assert()
 *
 * The compiler, during optimization, is expected to prove that the
 * assertion is true.
 */
#define qemu_build_assert(test) \
    while (!(test))             \
    qemu_build_not_reached()

// TODO: move this elsewhere?
static inline void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len) {
}

#define LIBTCG_ERROR(X) __attribute__((error(X)))
NORETURN extern void LIBTCG_ERROR("code path is reachable") qemu_build_not_reached_always(void);

static inline void qemu_thread_jit_write(void) {
}
static inline void qemu_thread_jit_execute(void) {
}

#define QEMU_MADV_INVALID -1

int qemu_madvise(void *addr, size_t len, int advice);
int qemu_mprotect_rw(void *addr, size_t size);
int qemu_mprotect_rwx(void *addr, size_t size);
int qemu_mprotect_none(void *addr, size_t size);

static inline uintptr_t qemu_real_host_page_size(void) {
    return getpagesize();
}

static inline intptr_t qemu_real_host_page_mask(void) {
    return -(intptr_t) qemu_real_host_page_size();
}

size_t qemu_get_host_physmem(void);

#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct {                        \
        int : (x) ? -1 : 1;         \
    }

#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)

#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)

#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))

#ifdef CONFIG_CFI
/*
 * If CFI is enabled, use an attribute to disable cfi-icall on the following
 * function
 */
#define QEMU_DISABLE_CFI __attribute__((no_sanitize("cfi-icall")))
#else
/* If CFI is not enabled, use an empty define to not change the behavior */
#define QEMU_DISABLE_CFI
#endif

#ifdef __cplusplus
}
#endif

#endif
