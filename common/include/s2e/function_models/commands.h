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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE
 * LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef S2E_FUNCTION_MODEL_COMMANDS_H
#define S2E_FUNCTION_MODEL_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

// TODO replace this with a stack frame bound, check for mapped memory page, ...
static const unsigned MAX_STRLEN = 4096;

enum S2E_LIBCWRAPPER_COMMANDS {
    LIBCWRAPPER_STRCPY,
    LIBCWRAPPER_STRNCPY,
    LIBCWRAPPER_STRLEN,
    LIBCWRAPPER_STRCMP,
    LIBCWRAPPER_STRNCMP,
    LIBCWRAPPER_MEMCPY,
    LIBCWRAPPER_MEMCMP,
    LIBCWRAPPER_STRCAT,
    LIBCWRAPPER_STRNCAT,

    WRAPPER_CRC,
};

struct S2E_LIBCWRAPPER_COMMAND_STRCPY {
    uint64_t dst;
    uint64_t src;
    uint64_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRNCPY {
    uint64_t dst;
    uint64_t src;
    uint64_t n;
    uint64_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRLEN {
    uint64_t str;
    size_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRCMP {
    uint64_t str1;
    uint64_t str2;
    int ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRNCMP {
    uint64_t str1;
    uint64_t str2;
    uint64_t n;
    int ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_MEMCPY {
    uint64_t dst;
    uint64_t src;
    uint64_t n;
    uint64_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_MEMCMP {
    uint64_t str1;
    uint64_t str2;
    uint64_t n;
    int ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRCAT {
    uint64_t dst;
    uint64_t src;
    uint64_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND_STRNCAT {
    uint64_t dst;
    uint64_t src;
    uint64_t n;
    uint64_t ret;
} __attribute__((packed));

enum S2E_WRAPPER_CRC_TYPE { S2E_WRAPPER_CRC16, S2E_WRAPPER_CRC32 };

struct S2E_WRAPPER_COMMAND_CRC {
    enum S2E_WRAPPER_CRC_TYPE type;
    // Pointer to the initial CRC value
    uint64_t initial_value_ptr;
    uint64_t xor_result;
    uint64_t buffer;
    uint64_t size;
    uint64_t ret;
} __attribute__((packed));

struct S2E_LIBCWRAPPER_COMMAND {
    enum S2E_LIBCWRAPPER_COMMANDS Command;
    union {
        struct S2E_LIBCWRAPPER_COMMAND_STRCPY Strcpy;
        struct S2E_LIBCWRAPPER_COMMAND_STRNCPY Strncpy;
        struct S2E_LIBCWRAPPER_COMMAND_STRLEN Strlen;
        struct S2E_LIBCWRAPPER_COMMAND_STRCMP Strcmp;
        struct S2E_LIBCWRAPPER_COMMAND_STRNCMP Strncmp;
        struct S2E_LIBCWRAPPER_COMMAND_MEMCPY Memcpy;
        struct S2E_LIBCWRAPPER_COMMAND_MEMCMP Memcmp;
        struct S2E_LIBCWRAPPER_COMMAND_STRCAT Strcat;
        struct S2E_LIBCWRAPPER_COMMAND_STRNCAT Strncat;
        struct S2E_WRAPPER_COMMAND_CRC Crc;
    };
    uint64_t needOrigFunc;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
