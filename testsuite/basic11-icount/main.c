// Copyright (c) 2023, Vitaly Chipounov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define _GNU_SOURCE

#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>

#include <s2e/instruction_counter.h>
#include <s2e/monitors/support/thread_execution_detector.h>
#include <s2e/s2e.h>

// TODO: move the OS abstractions into a separate header file so
// that other tests can use them as well.
#ifdef _WIN32
#include <windows.h>

typedef HANDLE thread_t;

thread_t our_create_thread(void *fn) {
    return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) fn, NULL, 0, NULL);
}

void our_thread_join(thread_t handle) {
    WaitForSingleObject((HANDLE) handle, INFINITE);
}

pid_t our_gettid(void) {
    return GetCurrentThreadId();
}
#else
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

typedef pthread_t thread_t;

thread_t our_create_thread(void *fn) {
    pthread_t id;
    if (pthread_create(&id, NULL, fn, NULL) < 0) {
        return -1;
    }

    return id;
}

void our_thread_join(thread_t handle) {
    void *result;
    pthread_join(handle, (void **) &result);
}

pid_t our_gettid(void) {
    return syscall(SYS_gettid);
}
#endif

// Each loop iteration records the current value of the
// instruction counter. It must increase by a constant
// number of instructions at each iteration.
static void *test_icount(void *arg) {

    // Count instructions only within a small block of code.
    s2e_thread_exec_enable_current();
    s2e_icount_reset();
    uint64_t counts[16];

    for (int i = 0; i < 16; ++i) {
        counts[i] = s2e_icount_get();
        if (counts[i] == 0) {
            s2e_kill_state(0, "Got zero count");
        }
    }

    s2e_thread_exec_disable_current();

    uint64_t first_diff = 0;
    int fail = 0;

    pid_t pid = getpid();
    pid_t tid = our_gettid();

    // Check that instruction counts are constant.
    for (int i = 0; i < 16; ++i) {
        uint64_t diff = 0;
        if (i > 0) {
            diff = counts[i] - counts[i - 1];
            if (i == 1) {
                first_diff = diff;
            } else {
                if (diff != first_diff) {
                    fail = 1;
                }
            }
        }

        s2e_printf("pid=%d tid=%d icount[%d]=%" PRIu64 " diff=%" PRIu64, pid, tid, i, counts[i], diff);

        if (i > 0) {
            if (counts[i] == 0 || diff == 0) {
                s2e_kill_state(0, "incorrect count/diff");
            }
        }
    }

    if (fail) {
        s2e_kill_state(0, "icount bad");
    }

    return NULL;
}

static void invoke_syscall(void) {
#ifdef _WIN32
    // That's not a pid, but we don't really care.
    // We just want some syscall.
    // On Windows, getpid() doesn't result in a syscall.
    OpenProcess(READ_CONTROL, FALSE, 1234);
#else
    getpid();
#endif
}

///
/// @brief Test that the instruction counter properly handles syscalls.
///
/// It must be able to count kernel instructions when the tracking plugin
/// is instructed to track the kernel.
///
static int test_icount_syscall(int trace_kernel) {
    s2e_thread_exec_enable_current();
    if (trace_kernel) {
        s2e_thread_exec_enable_kernel_tracking();
    }

    s2e_icount_reset();

    invoke_syscall();

    int icount = s2e_icount_get();

    if (trace_kernel) {
        s2e_thread_exec_disable_kernel_tracking();
    }

    s2e_thread_exec_disable_current();

    s2e_printf("trace_kernel=%d icount=%d\n", trace_kernel, icount);

    return icount;
}

int main(int argc, char **argv) {
    thread_t threads[16];

    int c1 = test_icount_syscall(0);
    int c2 = test_icount_syscall(1);
    if (!c1 || !c2) {
        s2e_kill_state(0, "icount is zero");
    }

    if (c2 <= c1) {
        s2e_kill_state(0, "icount is wrong");
    }

    for (int i = 0; i < 16; ++i) {
        threads[i] = our_create_thread(test_icount);
    }

    for (int i = 0; i < 16; ++i) {
        our_thread_join(threads[i]);
    }

    s2e_kill_state(0, "icount good");

    return 0;
}
