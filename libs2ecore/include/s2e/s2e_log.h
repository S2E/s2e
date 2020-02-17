///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <stdarg.h>

#ifndef __S2E_LOG__H__

#define __S2E_LOG__H__

#ifdef __cplusplus
extern "C" {
#endif

void s2e_flush_output_streams(void);
void s2e_debug_print(const char *fmtstr, ...);
void s2e_warning_print(const char *fmtstr, ...);
int s2e_vprintf(const char *fmtstr, int warn, va_list args);
void s2e_debug_print_hex(void *addr, int len);
void print_stacktrace(void (*print_func)(const char *fmt, ...), const char *reason);

#ifdef __cplusplus
}
#endif

#endif
