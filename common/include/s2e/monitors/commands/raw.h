/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_RAW_COMMANDS_H
#define S2E_RAW_COMMANDS_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

enum S2E_RAWMON_COMMANDS {
    RAW_MODULE_LOAD,
    RAW_SET_CURRENT_STACK,
};

struct S2E_RAWMON_COMMAND_MODULE_LOAD {
    uint64_t path;
    uint64_t name;
    uint64_t native_base;
    uint64_t load_base;
    uint64_t entry_point;
    uint64_t size;
    uint64_t pid;
    uint64_t kernel_mode;
} __attribute__((packed));

struct S2E_RAWMON_COMMAND_STACK {
    uint64_t guest_stack_descriptor_ptr;
    uint64_t stack_base;
    uint64_t stack_size;
} __attribute__((packed));

struct S2E_RAWMON_COMMAND {
    enum S2E_RAWMON_COMMANDS Command;
    union {
        struct S2E_RAWMON_COMMAND_MODULE_LOAD ModuleLoad;
        struct S2E_RAWMON_COMMAND_STACK Stack;
    };
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
