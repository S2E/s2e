/*
 * Simple C functions to supplement the C library
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cutils.h"

#include <qapi/helpers.h>

static int64_t suffix_mul(char suffix, int64_t unit) {
    switch (toupper(suffix)) {
        case 'B':
            return 1;
        case 'K':
            return unit;
        case 'M':
            return unit * unit;
        case 'G':
            return unit * unit * unit;
        case 'T':
            return unit * unit * unit * unit;
        case 'P':
            return unit * unit * unit * unit * unit;
        case 'E':
            return unit * unit * unit * unit * unit * unit;
    }
    return -1;
}

static inline void mulu64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b) {
    __uint128_t r = (__uint128_t) a * b;
    *plow = r;
    *phigh = r >> 64;
}

/*
 * Convert size string to bytes.
 *
 * The size parsing supports the following syntaxes
 * - 12345 - decimal, scale determined by @default_suffix and @unit
 * - 12345{bBkKmMgGtTpPeE} - decimal, scale determined by suffix and @unit
 * - 12345.678{kKmMgGtTpPeE} - decimal, scale determined by suffix, and
 *   fractional portion is truncated to byte
 * - 0x7fEE - hexadecimal, unit determined by @default_suffix
 *
 * The following cause a deprecation warning, and may be removed in the future
 * - 0xabc{kKmMgGtTpP} - hex with scaling suffix
 *
 * The following are intentionally not supported
 * - octal, such as 08
 * - fractional hex, such as 0x1.8
 * - floating point exponents, such as 1e3
 *
 * The end pointer will be returned in *end, if not NULL.  If there is
 * no fraction, the input can be decimal or hexadecimal; if there is a
 * fraction, then the input must be decimal and there must be a suffix
 * (possibly by @default_suffix) larger than Byte, and the fractional
 * portion may suffer from precision loss or rounding.  The input must
 * be positive.
 *
 * Return -ERANGE on overflow (with *@end advanced), and -EINVAL on
 * other error (with *@end left unchanged).
 */
static int do_strtosz(const char *nptr, const char **end, const char default_suffix, int64_t unit, uint64_t *result) {
    int retval;
    const char *endptr, *f;
    unsigned char c;
    bool hex = false;
    uint64_t val, valf = 0;
    int64_t mul;

    /* Parse integral portion as decimal. */
    retval = libq_strtou64(nptr, &endptr, 10, &val);
    if (retval) {
        goto out;
    }
    if (memchr(nptr, '-', endptr - nptr) != NULL) {
        endptr = nptr;
        retval = -EINVAL;
        goto out;
    }
    if (val == 0 && (*endptr == 'x' || *endptr == 'X')) {
        /* Input looks like hex, reparse, and insist on no fraction. */
        retval = libq_strtou64(nptr, &endptr, 16, &val);
        if (retval) {
            goto out;
        }
        if (*endptr == '.') {
            endptr = nptr;
            retval = -EINVAL;
            goto out;
        }
        hex = true;
    } else if (*endptr == '.') {
        /*
         * Input looks like a fraction.  Make sure even 1.k works
         * without fractional digits.  If we see an exponent, treat
         * the entire input as invalid instead.
         */
        double fraction;

        f = endptr;
        retval = libq_strtod_finite(f, &endptr, &fraction);
        if (retval) {
            endptr++;
        } else if (memchr(f, 'e', endptr - f) || memchr(f, 'E', endptr - f)) {
            endptr = nptr;
            retval = -EINVAL;
            goto out;
        } else {
            /* Extract into a 64-bit fixed-point fraction. */
            valf = (uint64_t) (fraction * 0x1p64);
        }
    }
    c = *endptr;
    mul = suffix_mul(c, unit);
    if (mul > 0) {
        if (hex) {
            fprintf(stderr,
                    "Using a multiplier suffix on hex numbers "
                    "is deprecated: %s",
                    nptr);
        }
        endptr++;
    } else {
        mul = suffix_mul(default_suffix, unit);
        assert(mul > 0);
    }
    if (mul == 1) {
        /* When a fraction is present, a scale is required. */
        if (valf != 0) {
            endptr = nptr;
            retval = -EINVAL;
            goto out;
        }
    } else {
        uint64_t valh, tmp;

        /* Compute exact result: 64.64 x 64.0 -> 128.64 fixed point */
        mulu64(&val, &valh, val, mul);
        mulu64(&valf, &tmp, valf, mul);
        val += tmp;
        valh += val < tmp;

        /* Round 0.5 upward. */
        tmp = valf >> 63;
        val += tmp;
        valh += val < tmp;

        /* Report overflow. */
        if (valh != 0) {
            retval = -ERANGE;
            goto out;
        }
    }

    retval = 0;

out:
    if (end) {
        *end = endptr;
    } else if (*endptr) {
        retval = -EINVAL;
    }
    if (retval == 0) {
        *result = val;
    }

    return retval;
}

int libq_strtosz(const char *nptr, const char **end, uint64_t *result) {
    return do_strtosz(nptr, end, 'B', 1024, result);
}

/**
 * Helper function for error checking after strtol() and the like
 */
static int check_strtox_error(const char *nptr, char *ep, const char **endptr, bool check_zero, int libc_errno) {
    assert(ep >= nptr);

    /* Windows has a bug in that it fails to parse 0 from "0x" in base 16 */
    if (check_zero && ep == nptr && libc_errno == 0) {
        char *tmp;

        errno = 0;
        if (strtol(nptr, &tmp, 10) == 0 && errno == 0 && (*tmp == 'x' || *tmp == 'X')) {
            ep = tmp;
        }
    }

    if (endptr) {
        *endptr = ep;
    }

    /* Turn "no conversion" into an error */
    if (libc_errno == 0 && ep == nptr) {
        return -EINVAL;
    }

    /* Fail when we're expected to consume the string, but didn't */
    if (!endptr && *ep) {
        return -EINVAL;
    }

    return -libc_errno;
}

/**
 * Convert string @nptr to an integer, and store it in @result.
 *
 * This is a wrapper around strtol() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtol() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store INT_MAX in @result,
 * and return -ERANGE.
 *
 * If the conversion underflows @result, store INT_MIN in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int libq_strtoi(const char *nptr, const char **endptr, int base, int *result) {
    char *ep;
    long long lresult;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    lresult = strtoll(nptr, &ep, base);
    if (lresult < INT_MIN) {
        *result = INT_MIN;
        errno = ERANGE;
    } else if (lresult > INT_MAX) {
        *result = INT_MAX;
        errno = ERANGE;
    } else {
        *result = lresult;
    }
    return check_strtox_error(nptr, ep, endptr, lresult == 0, errno);
}

/**
 * Convert string @nptr to an unsigned integer, and store it in @result.
 *
 * This is a wrapper around strtoul() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtoul() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store UINT_MAX in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 *
 * Note that a number with a leading minus sign gets converted without
 * the minus sign, checked for overflow (see above), then negated (in
 * @result's type).  This is exactly how strtoul() works.
 */
int libq_strtoui(const char *nptr, const char **endptr, int base, unsigned int *result) {
    char *ep;
    long long lresult;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    lresult = strtoull(nptr, &ep, base);

    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    } else {
        if (lresult > UINT_MAX) {
            *result = UINT_MAX;
            errno = ERANGE;
        } else if (lresult < INT_MIN) {
            *result = UINT_MAX;
            errno = ERANGE;
        } else {
            *result = lresult;
        }
    }
    return check_strtox_error(nptr, ep, endptr, lresult == 0, errno);
}

/**
 * Convert string @nptr to a long integer, and store it in @result.
 *
 * This is a wrapper around strtol() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtol() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store LONG_MAX in @result,
 * and return -ERANGE.
 *
 * If the conversion underflows @result, store LONG_MIN in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int libq_strtol(const char *nptr, const char **endptr, int base, long *result) {
    char *ep;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtol(nptr, &ep, base);
    return check_strtox_error(nptr, ep, endptr, *result == 0, errno);
}

/**
 * Convert string @nptr to an unsigned long, and store it in @result.
 *
 * This is a wrapper around strtoul() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtoul() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store ULONG_MAX in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 *
 * Note that a number with a leading minus sign gets converted without
 * the minus sign, checked for overflow (see above), then negated (in
 * @result's type).  This is exactly how strtoul() works.
 */
int libq_strtoul(const char *nptr, const char **endptr, int base, unsigned long *result) {
    char *ep;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtoul(nptr, &ep, base);
    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    }
    return check_strtox_error(nptr, ep, endptr, *result == 0, errno);
}

/**
 * Convert string @nptr to an int64_t.
 *
 * Works like libq_strtol(), except it stores INT64_MAX on overflow,
 * and INT64_MIN on underflow.
 */
int libq_strtoi64(const char *nptr, const char **endptr, int base, int64_t *result) {
    char *ep;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    /* This assumes int64_t is long long TODO relax */
    LIBQ_BUILD_BUG_ON(sizeof(int64_t) != sizeof(long long));
    errno = 0;
    *result = strtoll(nptr, &ep, base);
    return check_strtox_error(nptr, ep, endptr, *result == 0, errno);
}

/**
 * Convert string @nptr to an uint64_t.
 *
 * Works like libq_strtoul(), except it stores UINT64_MAX on overflow.
 */
int libq_strtou64(const char *nptr, const char **endptr, int base, uint64_t *result) {
    char *ep;

    assert((unsigned) base <= 36 && base != 1);
    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    /* This assumes uint64_t is unsigned long long TODO relax */
    LIBQ_BUILD_BUG_ON(sizeof(uint64_t) != sizeof(unsigned long long));
    errno = 0;
    *result = strtoull(nptr, &ep, base);
    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    }
    return check_strtox_error(nptr, ep, endptr, *result == 0, errno);
}

/**
 * Convert string @nptr to a double.
 *
 * This is a wrapper around strtod() that is harder to misuse.
 * Semantics of @nptr and @endptr match strtod() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL. This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows, store +/-HUGE_VAL in @result, depending
 * on the sign, and return -ERANGE.
 *
 * If the conversion underflows, store +/-0.0 in @result, depending on the
 * sign, and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int libq_strtod(const char *nptr, const char **endptr, double *result) {
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtod(nptr, &ep);
    return check_strtox_error(nptr, ep, endptr, false, errno);
}

/**
 * Convert string @nptr to a finite double.
 *
 * Works like libq_strtod(), except that "NaN" and "inf" are rejected
 * with -EINVAL and no conversion is performed.
 */
int libq_strtod_finite(const char *nptr, const char **endptr, double *result) {
    double tmp;
    int ret;

    ret = libq_strtod(nptr, endptr, &tmp);
    if (!ret && !isfinite(tmp)) {
        if (endptr) {
            *endptr = nptr;
        }
        ret = -EINVAL;
    }

    if (ret != -EINVAL) {
        *result = tmp;
    }
    return ret;
}