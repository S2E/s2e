/* public domain */

#ifndef COMPILER_H
#define COMPILER_H

#include <cpu/config-host.h>

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------
| The macro LIBCPU_GNUC_PREREQ tests for minimum version of the GNU C compiler.
| The code is a copy of SOFTFLOAT_GNUC_PREREQ, see softfloat-macros.h.
*----------------------------------------------------------------------------*/
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define LIBCPU_GNUC_PREREQ(maj, min) ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define LIBCPU_GNUC_PREREQ(maj, min) 0
#endif

#define LIBCPU_NORETURN __attribute__((__noreturn__))

#if defined(_WIN32)
#define LIBCPU_PACKED __attribute__((gcc_struct, packed))
#else
#define LIBCPU_PACKED __attribute__((packed))
#endif

#if defined __GNUC__
#if !LIBCPU_GNUC_PREREQ(4, 4)
/* gcc versions before 4.4.x don't support gnu_printf, so use printf. */
#define GCC_ATTR __attribute__((__unused__, format(printf, 1, 2)))
#define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
#else
#define GCC_ATTR __attribute__((__unused__, format(gnu_printf, 1, 2)))
#define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
#endif
#else
#define GCC_ATTR /**/
#define GCC_FMT_ATTR(n, m)
#endif

#define typeof __typeof__

#ifndef likely
#if __GNUC__ < 3
#define __builtin_expect(x, n) (x)
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif /* COMPILER_H */
