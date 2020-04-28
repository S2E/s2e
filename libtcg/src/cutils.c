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
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <tcg/utils/cutils.h>

static int64_t suffix_mul(char suffix, int64_t unit) {
    switch (toupper(suffix)) {
        case STRTOSZ_DEFSUFFIX_B:
            return 1;
        case STRTOSZ_DEFSUFFIX_KB:
            return unit;
        case STRTOSZ_DEFSUFFIX_MB:
            return unit * unit;
        case STRTOSZ_DEFSUFFIX_GB:
            return unit * unit * unit;
        case STRTOSZ_DEFSUFFIX_TB:
            return unit * unit * unit * unit;
    }
    return -1;
}

///
/// \brief strtosz_suffix_unit Convert string to bytes, allowing either B/b for bytes, K/k for KB,
/// M/m for MB, G/g for GB or T/t for TB. End pointer will be returned
/// in *end, if not NULL.
///
/// \param nptr
/// \param end
/// \param default_suffix
/// \param unit
/// \return -1 on error
///
int64_t strtosz_suffix_unit(const char *nptr, char **end, const char default_suffix, int64_t unit) {
    int64_t retval = -1;
    char *endptr;
    unsigned char c;
    int mul_required = 0;
    double val, mul, integral, fraction;

    errno = 0;
    val = strtod(nptr, &endptr);
    if (__builtin_isnan(val) || endptr == nptr || errno != 0) {
        goto fail;
    }
    fraction = modf(val, &integral);
    if (fraction != 0) {
        mul_required = 1;
    }
    c = *endptr;
    mul = suffix_mul(c, unit);
    if (mul >= 0) {
        endptr++;
    } else {
        mul = suffix_mul(default_suffix, unit);
        assert(mul >= 0);
    }
    if (mul == 1 && mul_required) {
        goto fail;
    }
    if (((long) (val * mul) >= INT64_MAX) || val < 0) {
        goto fail;
    }
    retval = val * mul;

fail:
    if (end) {
        *end = endptr;
    }

    return retval;
}

int64_t strtosz_suffix(const char *nptr, char **end, const char default_suffix) {
    return strtosz_suffix_unit(nptr, end, default_suffix, 1024);
}

int64_t strtosz(const char *nptr, char **end) {
    return strtosz_suffix(nptr, end, STRTOSZ_DEFSUFFIX_MB);
}

void pstrcpy(char *buf, int buf_size, const char *str) {
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for (;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s) {
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}
