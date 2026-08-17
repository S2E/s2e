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

#ifndef LIBQ_CUTILS_H
#define LIBQ_CUTILS_H

#include <inttypes.h>

int libq_strtosz(const char *nptr, const char **end, uint64_t *result);

int libq_strtoi(const char *nptr, const char **endptr, int base, int *result);
int libq_strtoui(const char *nptr, const char **endptr, int base, unsigned int *result);
int libq_strtol(const char *nptr, const char **endptr, int base, long *result);
int libq_strtoul(const char *nptr, const char **endptr, int base, unsigned long *result);
int libq_strtoi64(const char *nptr, const char **endptr, int base, int64_t *result);
int libq_strtou64(const char *nptr, const char **endptr, int base, uint64_t *result);
int libq_strtod(const char *nptr, const char **endptr, double *result);
int libq_strtod_finite(const char *nptr, const char **endptr, double *result);

#endif
