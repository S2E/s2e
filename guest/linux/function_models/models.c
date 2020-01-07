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

#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdint.h>
#include <stdio.h>

#include <s2e/function_models/commands.h>
#include <s2e/s2e.h>

#include "function_models.h"

// Initialize copies of the modelled functions
T_strcpy orig_strcpy = NULL;
T_strncpy orig_strncpy = NULL;
T_strlen orig_strlen = NULL;
T_strcmp orig_strcmp = NULL;
T_strncmp orig_strncmp = NULL;
T_memcpy orig_memcpy = NULL;
T_memcmp orig_memcmp = NULL;
T_printf orig_printf = NULL;
T_fprintf orig_fprintf = NULL;
T_strcat orig_strcat = NULL;
T_strncat orig_strncat = NULL;

T_crc32 orig_crc32 = NULL;
T_crc16 orig_crc16 = NULL;

// Save the original functions so we can use them if required
void initialize_models() {
    orig_strcpy = (T_strcpy) dlsym(RTLD_NEXT, "strcpy");
    orig_strncpy = (T_strncpy) dlsym(RTLD_NEXT, "strncpy");
    orig_strlen = (T_strlen) dlsym(RTLD_NEXT, "strlen");
    orig_strcmp = (T_strcmp) dlsym(RTLD_NEXT, "strcmp");
    orig_strncmp = (T_strncmp) dlsym(RTLD_NEXT, "strncmp");
    orig_memcpy = (T_memcpy) dlsym(RTLD_NEXT, "memcpy");
    orig_memcmp = (T_memcmp) dlsym(RTLD_NEXT, "memcmp");
    orig_printf = (T_printf) dlsym(RTLD_NEXT, "printf");
    orig_fprintf = (T_fprintf) dlsym(RTLD_NEXT, "fprintf");
    orig_strcat = (T_strcat) dlsym(RTLD_NEXT, "strcat");
    orig_strncat = (T_strncat) dlsym(RTLD_NEXT, "strncat");

    orig_crc32 = (T_crc32) dlsym(RTLD_NEXT, "crc32");
    orig_crc16 = (T_crc16) dlsym(RTLD_NEXT, "crc16");
}

char *strcpy_model(char *dest, const char *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strcpy)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_strcpy)(dest, src);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCPY;
    cmd.Strcpy.dst = (uintptr_t) dest;
    cmd.Strcpy.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strcpy)(dest, src);
}

char *strncpy_model(char *dest, const char *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strncpy)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_strncpy)(dest, src, n);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCPY;
    cmd.Strncpy.dst = (uintptr_t) dest;
    cmd.Strncpy.src = (uintptr_t) src;
    cmd.Strncpy.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strncpy)(dest, src, n);
}

size_t strlen_model(const char *str) {
    if (s2e_is_symbolic(&str, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strlen)(str);
    }

    if (str == NULL) {
        return (*orig_strlen)(str);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRLEN;
    cmd.Strlen.str = (uintptr_t) str;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strlen.ret;
    }

    return (*orig_strlen)(str);
}

int strcmp_model(const char *str1, const char *str2) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strcmp)(str1, str2);
    }

    if (!str1 || !str2) {
        return (*orig_strcmp)(str1, str2);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRCMP;
    cmd.Strcmp.str1 = (uintptr_t) str1;
    cmd.Strcmp.str2 = (uintptr_t) str2;
    cmd.needOrigFunc = 1;
    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strcmp.ret;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strcmp)(str1, str2);
}

int strncmp_model(const char *str1, const char *str2, size_t n) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strncmp)(str1, str2, n);
    }

    if (!str1 || !str2) {
        return (*orig_strncmp)(str1, str2, n);
    }

    if (!n) {
        return 0;
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCMP;
    cmd.Strncmp.str1 = (uintptr_t) str1;
    cmd.Strncmp.str2 = (uintptr_t) str2;
    cmd.Strncmp.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strncmp.ret;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strncmp)(str1, str2, n);
}

void *memcpy_model(void *dest, const void *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_memcpy)(dest, src, n);
    }

    if (!dest || !src) {
        return (*orig_memcpy)(dest, src, n);
    }

    if (!n) {
        return dest;
    }

    if (n > MAX_STRLEN) {
        return (*orig_memcpy)(dest, src, n);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_MEMCPY;
    cmd.Memcpy.dst = (uintptr_t) dest;
    cmd.Memcpy.src = (uintptr_t) src;
    cmd.Memcpy.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return (void *) dest;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_memcpy)(dest, src, n);
}

int memcmp_model(const void *str1, const void *str2, size_t n) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_memcmp)(str1, str2, n);
    }

    if (!str1 || !str2 || !n) {
        return (*orig_memcmp)(str1, str2, n);
    }

    if (n > MAX_STRLEN) {
        return (*orig_memcmp)(str1, str2, n);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_MEMCMP;
    cmd.Memcmp.str1 = (uintptr_t) str1;
    cmd.Memcmp.str2 = (uintptr_t) str2;
    cmd.Memcmp.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        if (s2e_is_symbolic(&cmd.Memcmp.ret, sizeof(int))) {
            s2e_message("return value is symbolic");
        }

        return cmd.Memcmp.ret;
    }
    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_memcmp)(str1, str2, n);
}

char *strcat_model(char *dest, const char *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strcat)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_strcat)(dest, src);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCAT;
    cmd.Strcat.dst = (uintptr_t) dest;
    cmd.Strcat.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strcat)(dest, src);
}

char *strncat_model(char *dest, const char *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet!");
        return (*orig_strncat)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_strncat)(dest, src, n);
    }

    if (n > MAX_STRLEN) {
        return (*orig_strncat)(dest, src, n);
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRNCAT;
    cmd.Strncat.dst = (uintptr_t) dest;
    cmd.Strncat.src = (uintptr_t) src;
    cmd.Strncat.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    // Touch here means Function model fails and then we use original function in libc.so
    return (*orig_strncat)(dest, src, n);
}

static uint8_t _printf_helper(const char *format) {
    if (s2e_is_symbolic(&format, sizeof(void *))) {
        s2e_message("Symbolic address for format string is not supported yet!");
        return 0;
    }

    unsigned i = 0;
    do {
        if (s2e_is_symbolic((void *) (format + i), sizeof(char))) {
            s2e_message("Warning: user controllable format string can cause vulnerability!");
            break;
        }
        if ('\0' == *(format + i)) { // check for null character
            break;
        }
    } while (1);

    return 1;
}

int printf_model(const char *format, ...) {
    _printf_helper(format);

    return 0; // FIXME: how to handle the return value
}

int fprintf_model(FILE *stream, const char *format, ...) {
    // Writing to files is currently not supported
    if (stream == stderr || stream == stdout) {
        _printf_helper(format);
        return 0;
    }

    va_list arg;
    int done;

    va_start(arg, format);
    done = vfprintf(stream, format, arg);
    va_end(arg);

    return done;
}

///
/// \brief crc32_model emulates the crc32 function in zlib
/// \param crc the initial crc
/// \param buf a pointer to the buffer
/// \param len the length of the buffer
/// \return the crc
///
uint32_t crc32_model(uint32_t crc, const uint8_t *buf, unsigned len) {
    if (!buf) {
        return 0;
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;

    cmd.Command = WRAPPER_CRC;
    cmd.Crc.initial_value_ptr = (uintptr_t) &crc;
    cmd.Crc.buffer = (uintptr_t) buf;
    cmd.Crc.size = len;
    cmd.Crc.xor_result = 1;
    cmd.Crc.type = S2E_WRAPPER_CRC32;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Crc.ret;
    }

    return (*orig_crc32)(crc, buf, len);
}

///
/// \brief crc16_model emulates the crc32 function
/// \param crc the initial crc
/// \param buf a pointer to the buffer
/// \param len the length of the buffer
/// \return the crc
///
uint16_t crc16_model(uint16_t crc, const uint8_t *buf, unsigned len) {
    if (!buf) {
        return 0;
    }

    struct S2E_LIBCWRAPPER_COMMAND cmd;

    cmd.Command = WRAPPER_CRC;
    cmd.Crc.initial_value_ptr = (uintptr_t) &crc;
    cmd.Crc.buffer = (uintptr_t) buf;
    cmd.Crc.size = len;
    cmd.Crc.type = S2E_WRAPPER_CRC16;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Crc.ret;
    }

    return (*orig_crc16)(crc, buf, len);
}
