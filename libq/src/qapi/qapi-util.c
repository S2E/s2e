/*
 * QAPI util functions
 *
 * Authors:
 *  Hu Tao       <hutao@cn.fujitsu.com>
 *  Peter Lieven <pl@kamp.de>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include <assert.h>
#include <ctype.h>

#include "qapi/error.h"
#include "qapi/qmp/qerror.h"

const char *qapi_enum_lookup(const QEnumLookup *lookup, int val) {
    assert(val >= 0 && val < lookup->size);

    return lookup->array[val];
}

int qapi_enum_parse(const QEnumLookup *lookup, const char *buf, int def, Error **errp) {
    int i;

    if (!buf) {
        return def;
    }

    for (i = 0; i < lookup->size; i++) {
        if (!strcmp(buf, lookup->array[i])) {
            return i;
        }
    }

    error_setg(errp, "invalid parameter value: %s", buf);
    return def;
}

bool qapi_bool_parse(const char *name, const char *value, bool *obj, Error **errp) {
    if (g_str_equal(value, "on") || g_str_equal(value, "yes") || g_str_equal(value, "true") ||
        g_str_equal(value, "y")) {
        *obj = true;
        return true;
    }
    if (g_str_equal(value, "off") || g_str_equal(value, "no") || g_str_equal(value, "false") ||
        g_str_equal(value, "n")) {
        *obj = false;
        return true;
    }

    error_setg(errp, QERR_INVALID_PARAMETER_VALUE, name, "'on' or 'off'");
    return false;
}

/*
 * Parse a valid QAPI name from @str.
 * A valid name consists of letters, digits, hyphen and underscore.
 * It may be prefixed by __RFQDN_ (downstream extension), where RFQDN
 * may contain only letters, digits, hyphen and period.
 * The special exception for enumeration names is not implemented.
 * See docs/devel/qapi-code-gen.txt for more on QAPI naming rules.
 * Keep this consistent with scripts/qapi-gen.py!
 * If @complete, the parse fails unless it consumes @str completely.
 * Return its length on success, -1 on failure.
 */
int parse_qapi_name(const char *str, bool complete) {
    const char *p = str;

    if (*p == '_') { /* Downstream __RFQDN_ */
        p++;
        if (*p != '_') {
            return -1;
        }
        while (*++p) {
            if (!isalnum(*p) && *p != '-' && *p != '.') {
                break;
            }
        }

        if (*p != '_') {
            return -1;
        }
        p++;
    }

    if (!isalpha(*p)) {
        return -1;
    }
    while (*++p) {
        if (!isalnum(*p) && *p != '-' && *p != '_') {
            break;
        }
    }

    if (complete && *p) {
        return -1;
    }
    return p - str;
}
