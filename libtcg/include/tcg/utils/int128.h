#ifndef INT128_H
#define INT128_H

#include <assert.h>
#include <stdbool.h>

#include "bswap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef __int128_t Int128;

static inline Int128 int128_make64(uint64_t a) {
    return a;
}

static inline Int128 int128_makes64(int64_t a) {
    return a;
}

static inline Int128 int128_make128(uint64_t lo, uint64_t hi) {
    return (__uint128_t) hi << 64 | lo;
}

static inline uint64_t int128_get64(Int128 a) {
    uint64_t r = a;
    assert(r == a);
    return r;
}

static inline uint64_t int128_getlo(Int128 a) {
    return a;
}

static inline int64_t int128_gethi(Int128 a) {
    return a >> 64;
}

static inline Int128 int128_zero(void) {
    return 0;
}

static inline Int128 int128_one(void) {
    return 1;
}

static inline Int128 int128_2_64(void) {
    return (Int128) 1 << 64;
}

static inline Int128 int128_exts64(int64_t a) {
    return a;
}

static inline Int128 int128_not(Int128 a) {
    return ~a;
}

static inline Int128 int128_and(Int128 a, Int128 b) {
    return a & b;
}

static inline Int128 int128_or(Int128 a, Int128 b) {
    return a | b;
}

static inline Int128 int128_xor(Int128 a, Int128 b) {
    return a ^ b;
}

static inline Int128 int128_rshift(Int128 a, int n) {
    return a >> n;
}

static inline Int128 int128_urshift(Int128 a, int n) {
    return (__uint128_t) a >> n;
}

static inline Int128 int128_lshift(Int128 a, int n) {
    return a << n;
}

static inline Int128 int128_add(Int128 a, Int128 b) {
    return a + b;
}

static inline Int128 int128_neg(Int128 a) {
    return -a;
}

static inline Int128 int128_sub(Int128 a, Int128 b) {
    return a - b;
}

static inline bool int128_nonneg(Int128 a) {
    return a >= 0;
}

static inline bool int128_eq(Int128 a, Int128 b) {
    return a == b;
}

static inline bool int128_ne(Int128 a, Int128 b) {
    return a != b;
}

static inline bool int128_ge(Int128 a, Int128 b) {
    return a >= b;
}

static inline bool int128_uge(Int128 a, Int128 b) {
    return ((__uint128_t) a) >= ((__uint128_t) b);
}

static inline bool int128_lt(Int128 a, Int128 b) {
    return a < b;
}

static inline bool int128_ult(Int128 a, Int128 b) {
    return (__uint128_t) a < (__uint128_t) b;
}

static inline bool int128_le(Int128 a, Int128 b) {
    return a <= b;
}

static inline bool int128_gt(Int128 a, Int128 b) {
    return a > b;
}

static inline bool int128_nz(Int128 a) {
    return a != 0;
}

static inline Int128 int128_min(Int128 a, Int128 b) {
    return a < b ? a : b;
}

static inline Int128 int128_max(Int128 a, Int128 b) {
    return a > b ? a : b;
}

static inline void int128_addto(Int128 *a, Int128 b) {
    *a += b;
}

static inline void int128_subfrom(Int128 *a, Int128 b) {
    *a -= b;
}

static inline Int128 bswap128(Int128 a) {
#if __has_builtin(__builtin_bswap128)
    return __builtin_bswap128(a);
#else
    return int128_make128(bswap64(int128_gethi(a)), bswap64(int128_getlo(a)));
#endif
}

static inline int clz128(Int128 a) {
    if (a >> 64) {
        return __builtin_clzll(a >> 64);
    } else {
        return (a) ? __builtin_clzll((uint64_t) a) + 64 : 128;
    }
}

static inline Int128 int128_divu(Int128 a, Int128 b) {
    return (__uint128_t) a / (__uint128_t) b;
}

static inline Int128 int128_remu(Int128 a, Int128 b) {
    return (__uint128_t) a % (__uint128_t) b;
}

static inline Int128 int128_divs(Int128 a, Int128 b) {
    return a / b;
}

static inline Int128 int128_rems(Int128 a, Int128 b) {
    return a % b;
}

static inline void bswap128s(Int128 *s) {
    *s = bswap128(*s);
}

#define UINT128_MAX int128_make128(~0LL, ~0LL)
#define INT128_MAX  int128_make128(UINT64_MAX, INT64_MAX)
#define INT128_MIN  int128_make128(0, INT64_MIN)

#ifdef __cplusplus
}
#endif

#endif /* INT128_H */
