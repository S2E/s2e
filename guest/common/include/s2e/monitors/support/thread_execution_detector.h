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

#ifndef S2E_THREADEXECDETECTOR_H
#define S2E_THREADEXECDETECTOR_H

#include <inttypes.h>
#include <memory.h>

#if !defined(LIBS2E_PLUGINS)
#include <s2e/s2e.h>
#endif

#ifdef __cplusplus
namespace s2e {
namespace plugins {
extern "C" {
#endif

enum S2E_THREADEXECDETECTOR_COMMANDS {
    THREADEXEC_ENABLE_KERNEL_TRACKING,
    THREADEXEC_DISABLE_KERNEL_TRACKING,
    THREADEXEC_ENABLE_CURRENT,
    THREADEXEC_DISABLE_CURRENT
};

struct S2E_THREADEXECDETECTOR_COMMAND {
    enum S2E_THREADEXECDETECTOR_COMMANDS Command;
} __attribute__((packed));

#if !defined(LIBS2E_PLUGINS)
static void s2e_thread_exec_enable_kernel_tracking() {
    struct S2E_THREADEXECDETECTOR_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = THREADEXEC_ENABLE_KERNEL_TRACKING;
    s2e_invoke_plugin("ThreadExecutionDetector", &cmd, sizeof(cmd));
}

static void s2e_thread_exec_disable_kernel_tracking() {
    struct S2E_THREADEXECDETECTOR_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = THREADEXEC_DISABLE_KERNEL_TRACKING;
    s2e_invoke_plugin("ThreadExecutionDetector", &cmd, sizeof(cmd));
}

static void s2e_thread_exec_enable_current() {
    struct S2E_THREADEXECDETECTOR_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = THREADEXEC_ENABLE_CURRENT;
    s2e_invoke_plugin("ThreadExecutionDetector", &cmd, sizeof(cmd));
}

static void s2e_thread_exec_disable_current() {
    struct S2E_THREADEXECDETECTOR_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = THREADEXEC_DISABLE_CURRENT;
    s2e_invoke_plugin("ThreadExecutionDetector", &cmd, sizeof(cmd));
}
#endif

#ifdef __cplusplus
}
}
}
#endif

#endif
