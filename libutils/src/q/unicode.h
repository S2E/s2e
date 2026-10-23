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

#ifndef LIBQ_UNICODE

#define LIBQ_UNICODE

#include <sys/types.h>

int mod_utf8_codepoint(const char *s, size_t n, char **end);
ssize_t mod_utf8_encode(char buf[], size_t bufsz, int codepoint);

#endif