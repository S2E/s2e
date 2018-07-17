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

#include <s2e/function_models/models.h>
#include <s2e/function_models/s2e_so.h>

// ****************************
// Overriding libc functions
// ****************************

char *strcpy(char *dest, const char *src) {
    if (!g_enable_function_models) {
        if (!orig_strcpy) {
            initialize_models();
        }

        return (*orig_strcpy)(dest, src);
    }

    return strcpy_model(dest, src);
}

char *strncpy(char *dest, const char *src, size_t n) {
    if (!g_enable_function_models) {
        if (!orig_strncpy) {
            initialize_models();
        }

        return (*orig_strncpy)(dest, src, n);
    }
    return strncpy_model(dest, src, n);
}

size_t strlen(const char *str) {
    if (!g_enable_function_models) {
        if (!orig_strlen) {
            initialize_models();
        }

        return (*orig_strlen)(str);
    }

    return strlen_model(str);
}

int strcmp(const char *str1, const char *str2) {
    if (!g_enable_function_models) {
        if (!orig_strcmp) {
            initialize_models();
        }

        return (*orig_strcmp)(str1, str2);
    }

    return strcmp_model(str1, str2);
}

int strncmp(const char *str1, const char *str2, size_t n) {
    if (!g_enable_function_models) {
        if (!orig_strncmp) {
            initialize_models();
        }

        return (*orig_strncmp)(str1, str2, n);
    }

    return strncmp_model(str1, str2, n);
}

void *memcpy(void *dest, const void *src, size_t n) {
    if (!g_enable_function_models) {
        if (!orig_memcpy) {
            initialize_models();
        }

        return (*orig_memcpy)(dest, src, n);
    }

    return memcpy_model(dest, src, n);
}

int memcmp(const void *str1, const void *str2, size_t n) {
    if (!g_enable_function_models) {
        if (!orig_memcmp) {
            initialize_models();
        }

        return (*orig_memcmp)(str1, str2, n);
    }

    return memcmp_model(str1, str2, n);
}

char *strcat(char *dest, const char *src) {
    if (!g_enable_function_models) {
        if (!orig_strcat) {
            initialize_models();
        }

        return (*orig_strcat)(dest, src);
    }

    return strcat_model(dest, src);
}

char *strncat(char *dest, const char *src, size_t n) {
    if (!g_enable_function_models) {
        if (!orig_strncat) {
            initialize_models();
        }

        return (*orig_strncat)(dest, src, n);
    }

    return strncat_model(dest, src, n);
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
