/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2023, Vitaly Chipounov
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

#ifndef S2E_INSTRUCTION_COUNTER_H
#define S2E_INSTRUCTION_COUNTER_H

#include <inttypes.h>
#include <memory.h>
#include <s2e/s2e.h>

#ifdef __cplusplus
extern "C" {
#endif

enum S2E_ICOUNT_COMMANDS { ICOUNT_RESET, ICOUNT_GET };

struct S2E_ICOUNT_COMMAND {
    enum S2E_ICOUNT_COMMANDS Command;
    union {
        uint64_t Count;
    };
} __attribute__((packed));

static void s2e_icount_reset() {
    struct S2E_ICOUNT_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = ICOUNT_RESET;
    s2e_invoke_plugin("InstructionCounter", &cmd, sizeof(cmd));
}

static uint64_t s2e_icount_get() {
    struct S2E_ICOUNT_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = ICOUNT_GET;
    s2e_invoke_plugin("InstructionCounter", &cmd, sizeof(cmd));
    return cmd.Count;
}

#ifdef __cplusplus
}
#endif

#endif
