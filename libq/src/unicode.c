/*
 * JSON Parser
 *
 * Copyright IBM, Corp. 2009
 * Copyright 2016 - Cyberhaven
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Vitaly Chipounov  <vitaly@cyberhaven.io>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "unicode.h"

// https://stackoverflow.com/questions/27415935/does-unicode-have-a-defined-maximum-number-of-code-points
static bool is_valid(int cp) {
    if (cp > 0x10FFFF) {
        return false;
    }

    if (cp >= 0xd800 && cp <= 0xdfff) {
        return false;
    }

    if (cp >= 0xfdd0 && cp <= 0xfdef) {
        return false;
    }

    if ((cp & 0xffff) == 0xfffe) {
        return false;
    }

    if ((cp & 0xffff) == 0xffff) {
        return false;
    }

    return true;
}

static int get_utf8_length(char b, int *cp) {
    int len = -1;
    if ((b & 0x80) == 0) {
        len = 1;
        *cp = b & 0x7f;
    } else if (((b & 0xe0) == 0xc0)) {
        len = 2;
        *cp = b & 0x1f;
    } else if (((b & 0xf0) == 0xe0)) {
        len = 3;
        *cp = b & 0xf;
    } else if (((b & 0xf8) == 0xf0)) {
        len = 4;
        *cp = b & 0x7;
    } else if (((b & 0xfc) == 0xf8)) {
        // 111110xx
        len = 5;
        *cp = b & 0x3;
    } else if (((b & 0xfe) == 0xfc)) {
        // 1111 110x
        len = 6;
        *cp = b & 0x1;
    }

    return len;
}

// Conversion table from https://en.wikipedia.org/wiki/UTF-8
int mod_utf8_codepoint(const char *s, size_t n, char **end) {
    int cp = -1;

    if (n == 0 || !*s) {
        return -1;
    }

    char b = *s++;

    int len = get_utf8_length(b, &cp);
    if (len < 0) {
        *end = (char *) s;
        return -1;
    }

    if (len == 1) {
        *end = (char *) s;
        if (!is_valid(cp)) {
            return -1;
        }
        return cp;
    }

    for (int i = 1; i < len; ++i) {
        if (i == n) {
            cp = -1;
            break;
        }

        b = *s;
        if ((b & 0xc0) != 0x80) {
            cp = -1;
            break;
        }
        ++s;
        cp = (cp << 6) | (b & 0x3f);
    }

    *end = (char *) s;

    if (!is_valid(cp)) {
        return -1;
    }

    static int min_cp[5] = {0x80, 0x800, 0x10000, 0x200000, 0x4000000};
    bool overlong = cp < min_cp[len - 2] && !(cp == 0 && len == 2);

    if (overlong) {
        return -1;
    }

    return cp;
}

static int wchar_to_utf8(uint32_t wchar, char *buffer, size_t buffer_length) {
    if (buffer_length < 5) {
        return -1;
    }

    if (!is_valid(wchar)) {
        return -1;
    }

    if (wchar > 0 && wchar <= 0x007F) {
        assert(buffer_length >= 2);

        buffer[0] = wchar & 0x7F;
        buffer[1] = 0;
        return 1;
    } else if (wchar <= 0x07FF) {
        assert(buffer_length >= 3);
        buffer[0] = 0xC0 | ((wchar >> 6) & 0x1F);
        buffer[1] = 0x80 | (wchar & 0x3F);
        buffer[2] = 0;
        return 2;
    } else if (wchar < 0xFFFF) {
        assert(buffer_length >= 4);

        buffer[0] = 0xE0 | ((wchar >> 12) & 0x0F);
        buffer[1] = 0x80 | ((wchar >> 6) & 0x3F);
        buffer[2] = 0x80 | (wchar & 0x3F);
        buffer[3] = 0;
        return 3;
    } else if (wchar < 0x10FFFF) {
        assert(buffer_length >= 5);

        buffer[0] = 0xF0 | ((wchar >> 18) & 0x07);
        buffer[1] = 0x80 | ((wchar >> 12) & 0x3F);
        buffer[2] = 0x80 | ((wchar >> 6) & 0x3F);
        buffer[3] = 0x80 | (wchar & 0x3F);
        buffer[4] = 0;
        return 4;
    }

    return -1;
}

ssize_t mod_utf8_encode(char buf[], size_t bufsz, int codepoint) {
    return wchar_to_utf8(codepoint, buf, bufsz);
}