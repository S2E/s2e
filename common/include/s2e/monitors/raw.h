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

#ifndef S2E_RAW_MONITOR_H
#define S2E_RAW_MONITOR_H

#include <memory.h>
#include <s2e/s2e.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "commands/raw.h"

static inline void s2e_raw_register_stack(struct S2E_RAWMON_COMMAND_STACK *stack) {
    struct S2E_RAWMON_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = RAW_SET_CURRENT_STACK;
    cmd.Stack.guest_stack_descriptor_ptr = (uintptr_t) stack;
    cmd.Stack.stack_base = 0;
    cmd.Stack.stack_size = 0;

    s2e_invoke_plugin("RawMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_raw_load_module(const struct S2E_RAWMON_COMMAND_MODULE_LOAD *module) {
    struct S2E_RAWMON_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = RAW_MODULE_LOAD;
    cmd.ModuleLoad = *module;

    s2e_invoke_plugin("RawMonitor", &cmd, sizeof(cmd));
}

#ifdef __cplusplus
}
#endif

#endif
