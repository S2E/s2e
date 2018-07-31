/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Dependable Systems Lab, EPFL
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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "function_models.h"
#include "s2e_so.h"

// ****************************
// Overriding libc functions
// ****************************

char *strcpy(char *dest, const char *src) {
    FUNC_MODEL_BODY(strcpy, dest, src);
}

char *strncpy(char *dest, const char *src, size_t n) {
    FUNC_MODEL_BODY(strncpy, dest, src, n);
}

size_t strlen(const char *str) {
    FUNC_MODEL_BODY(strlen, str);
}

int strcmp(const char *str1, const char *str2) {
    FUNC_MODEL_BODY(strcmp, str1, str2);
}

int strncmp(const char *str1, const char *str2, size_t n) {
    FUNC_MODEL_BODY(strncmp, str1, str2, n);
}

void *memcpy(void *dest, const void *src, size_t n) {
    FUNC_MODEL_BODY(memcpy, dest, src, n);
}

int memcmp(const void *str1, const void *str2, size_t n) {
    FUNC_MODEL_BODY(memcmp, str1, str2, n);
}

char *strcat(char *dest, const char *src) {
    FUNC_MODEL_BODY(strcat, dest, src);
}

char *strncat(char *dest, const char *src, size_t n) {
    FUNC_MODEL_BODY(strncat, dest, src, n);
}

int printf(const char *format, ...) {
    va_list arg;
    int done;

    va_start(arg, format);
    if (!g_enable_function_models) {
        done = vfprintf(stdout, format, arg);
    } else {
        done = printf_model(format, arg);
    }
    va_end(arg);

    return done;
}

int fprintf(FILE *stream, const char *format, ...) {
    va_list arg;
    int done;

    va_start(arg, format);
    if (!g_enable_function_models) {
        done = vfprintf(stream, format, arg);
    } else {
        done = fprintf_model(stream, format, arg);
    }
    va_end(arg);

    return done;
}
