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

#ifndef NORETURN
#define NORETURN __attribute__((noreturn))
#endif

// TODO: move this elsewhere?
static inline void flush_idcache_range(uintptr_t rx, uintptr_t rw, size_t len) {
}

#define LIBTCG_ERROR(X) __attribute__((error(X)))
extern _Noreturn void LIBTCG_ERROR("code path is reachable") qemu_build_not_reached_always(void);

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

#ifdef __cplusplus
}
#endif

#endif
