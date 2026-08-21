/*
 * OS includes and handling of OS dependencies
 *
 * This header exists to pull in some common system headers that
 * most code in QEMU will want, and to fix up some possible issues with
 * it (missing defines, Windows weirdness, and so on).
 *
 * To avoid getting into possible circular include dependencies, this
 * file should not include any other QEMU headers, with the exceptions
 * of config-host.h, config-target.h, qemu/compiler.h,
 * system/os-posix.h, system/os-win32.h, system/os-wasm.h, glib-compat.h and
 * qemu/typedefs.h, all of which are doing a similar job to this file
 * and are under similar constraints.
 *
 * This header also contains prototypes for functions defined in
 * os-*.c and util/oslib-*.c; those would probably be better split
 * out into separate header files.
 *
 * In an ideal world this header would contain only:
 *  (1) things which everybody needs
 *  (2) things without which code would work on most platforms but
 *      fail to compile or misbehave on a minority of host OSes
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_OSDEP_H
#define QEMU_OSDEP_H

#include <utils/compiler.h>
#include <utils/config-host.h>

/* Older versions of C++ don't get definitions of various macros from
 * stdlib.h unless we define these macros before first inclusion of
 * that system header.
 */
#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS
#endif
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mark a function that executes in coroutine context
 *
 * Functions that execute in coroutine context cannot be called directly from
 * normal functions.  In the future it would be nice to enable compiler or
 * static checker support for catching such errors.  This annotation might make
 * it possible and in the meantime it serves as documentation.
 *
 * For example:
 *
 *   static void coroutine_fn foo(void) {
 *       ....
 *   }
 */
#ifdef __clang__
#define coroutine_fn QEMU_ANNOTATE("coroutine_fn")
#else
#define coroutine_fn
#endif

/**
 * Mark a function that can suspend when executed in coroutine context,
 * but can handle running in non-coroutine context too.
 */
#ifdef __clang__
#define coroutine_mixed_fn QEMU_ANNOTATE("coroutine_mixed_fn")
#else
#define coroutine_mixed_fn
#endif

/**
 * Mark a function that should not be called from a coroutine context.
 * Usually there will be an analogous, coroutine_fn function that should
 * be used instead.
 *
 * When the function is also marked as coroutine_mixed_fn, the function should
 * only be called if the caller does not know whether it is in coroutine
 * context.
 *
 * Functions that are only no_coroutine_fn, on the other hand, should not
 * be called from within coroutines at all.  This for example includes
 * functions that block.
 *
 * In the future it would be nice to enable compiler or static checker
 * support for catching such errors.  This annotation is the first step
 * towards this, and in the meantime it serves as documentation.
 *
 * For example:
 *
 *   static void no_coroutine_fn foo(void) {
 *       ....
 *   }
 */
#ifdef __clang__
#define no_coroutine_fn QEMU_ANNOTATE("no_coroutine_fn")
#else
#define no_coroutine_fn
#endif

/*
 * For mingw, as of v6.0.0, the function implementing the assert macro is
 * not marked as noreturn, so the compiler cannot delete code following an
 * assert(false) as unused.  We rely on this within the code base to delete
 * code that is unreachable when features are disabled.
 * All supported versions of Glib's g_assert() satisfy this requirement.
 */
#ifdef __MINGW32__
#undef assert
#define assert(x) g_assert(x)
#endif

/**
 * qemu_build_not_reached()
 *
 * The compiler, during optimization, is expected to prove that a call
 * to this function cannot be reached and remove it.  If the compiler
 * supports QEMU_ERROR, this will be reported at compile time; otherwise
 * this will be reported at link time due to the missing symbol.
 */
G_NORETURN
void QEMU_ERROR("code path is reachable") qemu_build_not_reached_always(void);
#if defined(__OPTIMIZE__) && !defined(__NO_INLINE__)
#define qemu_build_not_reached() qemu_build_not_reached_always()
#else
#define qemu_build_not_reached() g_assert_not_reached()
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

/*
 * According to waitpid man page:
 * WCOREDUMP
 *  This  macro  is  not  specified  in POSIX.1-2001 and is not
 *  available on some UNIX implementations (e.g., AIX, SunOS).
 *  Therefore, enclose its use inside #ifdef WCOREDUMP ... #endif.
 */
#ifndef WCOREDUMP
#define WCOREDUMP(status) 0
#endif
/*
 * We have a lot of unaudited code that may fail in strange ways, or
 * even be a security risk during migration, if you disable assertions
 * at compile-time.  You may comment out these safety checks if you
 * absolutely want to disable assertion overhead, but it is not
 * supported upstream so the risk is all yours.  Meanwhile, please
 * submit patches to remove any side-effects inside an assertion, or
 * fixing error handling that should use Error instead of assert.
 */
/* S2E builds libtcg and libcpu with NDEBUG in release, so upstream's NDEBUG refusal is dropped here. */
#ifdef G_DISABLE_ASSERT
#error building with G_DISABLE_ASSERT is not supported
#endif

#ifndef OFF_MAX
#define OFF_MAX (sizeof(off_t) == 8 ? INT64_MAX : INT32_MAX)
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
#ifndef ENOMEDIUM
#define ENOMEDIUM ENODEV
#endif
#if !defined(ENOTSUP)
#define ENOTSUP 4096
#endif
#if !defined(ECANCELED)
#define ECANCELED 4097
#endif
#if !defined(EMEDIUMTYPE)
#define EMEDIUMTYPE 4098
#endif
#if !defined(ESHUTDOWN)
#define ESHUTDOWN 4099
#endif

#define RETRY_ON_EINTR(expr)                        \
    (__extension__({                                \
        typeof(expr) __result;                      \
        do {                                        \
            __result = (expr);                      \
        } while (__result == -1 && errno == EINTR); \
        __result;                                   \
    }))

/* time_t may be either 32 or 64 bits depending on the host OS, and
 * can be either signed or unsigned, so we can't just hardcode a
 * specific maximum value. This is not a C preprocessor constant,
 * so you can't use TIME_MAX in an #ifdef, but for our purposes
 * this isn't a problem.
 */

/* The macros TYPE_SIGNED, TYPE_WIDTH, and TYPE_MAXIMUM are from
 * Gnulib, and are under the LGPL v2.1 or (at your option) any
 * later version.
 */

/* True if the real type T is signed.  */
#define TYPE_SIGNED(t) (!((t) 0 < (t) - 1))

/* The width in bits of the integer type or expression T.
 * Padding bits are not supported.
 */
#define TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)

/* The maximum and minimum values for the integer type T.  */
#define TYPE_MAXIMUM(t) ((t) (!TYPE_SIGNED(t) ? (t) - 1 : ((((t) 1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))

#ifndef TIME_MAX
#define TIME_MAX TYPE_MAXIMUM(time_t)
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

/*
 * Use the same value as Linux for now.
 */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/* Mac OSX has a <stdint.h> bug that incorrectly defines SIZE_MAX with
 * the wrong type. Our replacement isn't usable in preprocessor
 * expressions, but it is sufficient for our needs. */
#ifdef HAVE_BROKEN_SIZE_MAX
#undef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#endif

/*
 * Two variations of MIN/MAX macros. The first is for runtime use, and
 * evaluates arguments only once (so it is safe even with side
 * effects), but will not work in constant contexts (such as array
 * size declarations) because of the '{}'.  The second is for constant
 * expression use, where evaluating arguments twice is safe because
 * the result is going to be constant anyway, but will not work in a
 * runtime context because of a void expression where a value is
 * expected.  Thus, both gcc and clang will fail to compile if you use
 * the wrong macro (even if the error may seem a bit cryptic).
 *
 * Note that neither form is usable as an #if condition; if you truly
 * need to write conditional code that depends on a minimum or maximum
 * determined by the pre-processor instead of the compiler, you'll
 * have to open-code it.  Sadly, Coverity is severely confused by the
 * constant variants, so we have to dumb things down there.
 *
 * Preprocessor sorcery ahead: use different identifiers for the local
 * variables in each expansion, so we can nest macro calls without
 * shadowing variables.
 */
#define MIN_INTERNAL(a, b, _a, _b)                \
    ({                                            \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b); \
        _a < _b ? _a : _b;                        \
    })
#undef MIN
#define MIN(a, b) MIN_INTERNAL((a), (b), MAKE_IDENTIFIER(_a), MAKE_IDENTIFIER(_b))

#define MAX_INTERNAL(a, b, _a, _b)                \
    ({                                            \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b); \
        _a > _b ? _a : _b;                        \
    })
#undef MAX
#define MAX(a, b) MAX_INTERNAL((a), (b), MAKE_IDENTIFIER(_a), MAKE_IDENTIFIER(_b))

#ifdef __COVERITY__
#define MIN_CONST(a, b) ((a) < (b) ? (a) : (b))
#define MAX_CONST(a, b) ((a) > (b) ? (a) : (b))
#else
#define MIN_CONST(a, b) \
    __builtin_choose_expr(__builtin_constant_p(a) && __builtin_constant_p(b), (a) < (b) ? (a) : (b), ((void) 0))
#define MAX_CONST(a, b) \
    __builtin_choose_expr(__builtin_constant_p(a) && __builtin_constant_p(b), (a) > (b) ? (a) : (b), ((void) 0))
#endif

/*
 * Minimum function that returns zero only if both values are zero.
 * Intended for use with unsigned values only.
 *
 * Preprocessor sorcery ahead: use different identifiers for the local
 * variables in each expansion, so we can nest macro calls without
 * shadowing variables.
 */
#define MIN_NON_ZERO_INTERNAL(a, b, _a, _b)            \
    ({                                                 \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);      \
        _a == 0 ? _b : (_b == 0 || _b > _a) ? _a : _b; \
    })
#define MIN_NON_ZERO(a, b) MIN_NON_ZERO_INTERNAL((a), (b), MAKE_IDENTIFIER(_a), MAKE_IDENTIFIER(_b))

/*
 * Round number down to multiple. Safe when m is not a power of 2 (see
 * ROUND_DOWN for a faster version when a power of 2 is guaranteed).
 */
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))

/*
 * Round number up to multiple. Safe when m is not a power of 2 (see
 * ROUND_UP for a faster version when a power of 2 is guaranteed).
 */
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

/* Check if n is a multiple of m */
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)

/* n-byte align pointer down */
#define QEMU_ALIGN_PTR_DOWN(p, n) ((typeof(p)) QEMU_ALIGN_DOWN((uintptr_t) (p), (n)))

/* n-byte align pointer up */
#define QEMU_ALIGN_PTR_UP(p, n) ((typeof(p)) QEMU_ALIGN_UP((uintptr_t) (p), (n)))

/* Check if pointer p is n-bytes aligned */
#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t) (p), (n))

/*
 * Round number down to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.
 */
#ifndef ROUND_DOWN
#define ROUND_DOWN(n, d) ((n) & -(0 ? (n) : (d)))
#endif

/*
 * Round number up to multiple. Requires that d be a power of 2 (see
 * QEMU_ALIGN_UP for a safer but slower version on arbitrary
 * numbers); works even if d is a smaller type than n.
 */
#ifndef ROUND_UP
#define ROUND_UP(n, d) ROUND_DOWN((n) + (d) - 1, (d))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

/*
 * &(x)[0] is always a pointer - if it's same type as x then the argument is a
 * pointer, not an array.
 */
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), typeof(&(x)[0])))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#endif

/* Using intptr_t ensures that qemu_*_page_mask is sign-extended even
 * when intptr_t is 32-bit and we are aligning a long long.
 */
static inline uintptr_t qemu_real_host_page_size(void) {
    return getpagesize();
}

static inline intptr_t qemu_real_host_page_mask(void) {
    return -(intptr_t) qemu_real_host_page_size();
}

/**
 * qemu_get_host_physmem:
 *
 * Operating system agnostic way of querying host memory.
 *
 * Returns amount of physical memory on the system. This is purely
 * advisery and may return 0 if we can't work it out. At the other
 * end we saturate to SIZE_MAX if you are lucky enough to have that
 * much memory.
 */
size_t qemu_get_host_physmem(void);

/*
 * Toggle write/execute on the pages marked MAP_JIT
 * for the current thread.
 */
#ifdef __APPLE__
static inline void qemu_thread_jit_execute(void) {
    pthread_jit_write_protect_np(true);
}

static inline void qemu_thread_jit_write(void) {
    pthread_jit_write_protect_np(false);
}
#else
static inline void qemu_thread_jit_write(void) {
}
static inline void qemu_thread_jit_execute(void) {
}
#endif

#ifdef __cplusplus
/* S2E keeps the plain forms for C++; the ones above rely on statement expressions and __builtin_types_compatible_p. */
#undef MIN
#undef MAX
#undef ARRAY_SIZE
#define MIN(a, b)     (((a) < (b)) ? (a) : (b))
#define MAX(a, b)     (((a) > (b)) ? (a) : (b))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef __cplusplus
}
#endif

#endif
