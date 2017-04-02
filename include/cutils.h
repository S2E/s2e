/// Simple C functions to supplement the C library
///
/// Copyright (c) 2006 Fabrice Bellard
/// Copyright (c) 2017 Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
/// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

#ifndef __LIBCPU_CUTILS_H__

#define __LIBCPU_CUTILS_H__

#include <inttypes.h>

// strtosz() suffixes used to specify the default treatment of an
// argument passed to strtosz() without an explicit suffix.
// These should be defined using upper case characters in the range
// A-Z, as strtosz() will use qemu_toupper() on the given argument
// prior to comparison.
#define STRTOSZ_DEFSUFFIX_TB 'T'
#define STRTOSZ_DEFSUFFIX_GB 'G'
#define STRTOSZ_DEFSUFFIX_MB 'M'
#define STRTOSZ_DEFSUFFIX_KB 'K'
#define STRTOSZ_DEFSUFFIX_B 'B'

int64_t strtosz_suffix_unit(const char *nptr, char **end, const char default_suffix, int64_t unit);

int64_t strtosz_suffix(const char *nptr, char **end, const char default_suffix);
int64_t strtosz(const char *nptr, char **end);

#endif
