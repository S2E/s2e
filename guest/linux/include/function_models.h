/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2017, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef S2E_FUNCTION_MODELS_H
#define S2E_FUNCTION_MODELS_H

#include <inttypes.h>
#include <stdio.h>

//
// Modelled functions types
//
typedef char *(*T_strcpy)(char *dest, const char *src);
typedef char *(*T_strncpy)(char *dest, const char *src, size_t n);

typedef size_t (*T_strlen)(const char *s);

typedef int (*T_strcmp)(const char *s1, const char *s2);
typedef int (*T_strncmp)(const char *s1, const char *s2, size_t n);

typedef void *(*T_memcpy)(void *dest, const void *src, size_t n);
typedef int (*T_memcmp)(const void *s1, const void *s2, size_t n);

typedef int (*T_printf)(const char *format, ...);
typedef int (*T_fprintf)(FILE *stream, const char *format, ...);

typedef char *(*T_strcat)(char *dest, const char *src);
typedef char *(*T_strncat)(char *dest, const char *src, size_t n);

typedef uint32_t (*T_crc32)(uint32_t crc, const uint8_t *buf, unsigned len);
typedef uint16_t (*T_crc16)(uint16_t crc, const uint8_t *buf, unsigned len);

//
// Pointers to copies of modelled functions
//
extern T_strcpy orig_strcpy;
extern T_strncpy orig_strncpy;
extern T_strlen orig_strlen;
extern T_strcmp orig_strcmp;
extern T_strncmp orig_strncmp;
extern T_memcpy orig_memcpy;
extern T_memcmp orig_memcmp;
extern T_printf orig_printf;
extern T_fprintf orig_fprintf;
extern T_strcat orig_strcat;
extern T_strncat orig_strncat;

extern T_crc32 orig_crc32;
extern T_crc16 orig_crc16;

/// Initialize the pointers to the original modelled functions
void initialize_models();

#define CONCAT__(x, y) x##_##y
#define CONCAT_(x, y)  CONCAT__(x, y)
#define CONCAT(x, y)   CONCAT_(x, y)

// clang-format off

#define FUNC_MODEL_BODY(func, ...)                 \
    if (!g_enable_function_models) {               \
        if (!CONCAT(orig, func)) {                 \
            initialize_models();                   \
        }                                          \
                                                   \
        return (*CONCAT(orig, func))(__VA_ARGS__); \
    }                                              \
                                                   \
    return CONCAT(func, model)(__VA_ARGS__);

// clang-format on

//
// Function model prototypes
//

char *strcpy_model(char *dest, const char *src);
char *strncpy_model(char *dest, const char *src, size_t n);

size_t strlen_model(const char *str);

int strcmp_model(const char *str1, const char *str2);
int strncmp_model(const char *str1, const char *str2, size_t n);

void *memcpy_model(void *dest, const void *src, size_t n);
int memcmp_model(const void *str1, const void *str2, size_t n);

char *strcat_model(char *dest, const char *src);
char *strncat_model(char *dest, const char *src, size_t n);

int printf_model(const char *format, ...);
int fprintf_model(FILE *stream, const char *format, ...);

uint32_t crc32_model(uint32_t crc, const uint8_t *buf, unsigned len);
uint16_t crc16_model(uint16_t crc, const uint8_t *buf, unsigned len);

#endif
