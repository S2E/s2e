// Copyright (c) 2026, Vitaly Chipounov
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

/// @file
/// Checks that a data breakpoint set through the debug registers traps right after
/// the instruction that writes to the watched address, and not later in the same
/// TB. The write happens natively first and then in KLEE, which S2E uses while a
/// register is symbolic. A second native write checks the trap when a full TB that
/// starts at the writing instruction is already in the jump cache.

#include <s2e/s2e.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// DR7: local enable of DR0, break on writes, 4 bytes long.
#define DR7_VALUE ((1UL << 0) | (1UL << 16) | (3UL << 18))
// DR6: DR0 was hit.
#define DR6_DR0_HIT 1UL

#ifdef __x86_64__
#define PC_OFFSET offsetof(struct user, regs.rip)
#else
#define PC_OFFSET offsetof(struct user, regs.eip)
#endif

static volatile uint32_t g_watched;
static volatile uint32_t g_unwatched;

// The addresses of the instructions that follow the writes. The nops keep these
// instructions in the same TB as the writes.
extern const char after_native_write[];
extern const char after_cached_write[];
extern const char after_klee_write[];

#define DEBUG_REG_OFFSET(i) (offsetof(struct user, u_debugreg) + (i) * sizeof(long))

/// Writes a value with one instruction that two different TBs can contain.
///
/// When the jump is taken, the write is the first instruction of a TB. When it is
/// not taken, the write is in the middle of the TB that starts after the jump.
///
/// @param ptr the address to write to
/// @param value the value to write
/// @param fall_through 0 to take the jump, any other value to skip it
static __attribute__((noinline)) void write_in_two_tbs(volatile uint32_t *ptr, uint32_t value, uint32_t fall_through) {
    __asm__ __volatile__("test %[fall_through], %[fall_through]\n"
                         "jz 1f\n"
                         "nop\n"
                         "nop\n"
                         "1:\n"
                         "movl %[value], (%[ptr])\n"
                         ".globl after_cached_write\n"
                         "after_cached_write:\n"
                         "nop\n"
                         "nop\n"
                         : /* no outputs */
                         : [ptr] "r"(ptr), [value] "r"(value), [fall_through] "r"(fall_through)
                         : "memory", "cc");
}

static void child(void) {
    uint32_t sym = 0;

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    raise(SIGSTOP);

    __asm__ __volatile__("movl $1, %[watched]\n"
                         ".globl after_native_write\n"
                         "after_native_write:\n"
                         "nop\n"
                         "nop\n"
                         : [watched] "=m"(g_watched));

    // The first call puts the TB that starts at the write in the jump cache. The
    // second call hits the breakpoint in the other TB, so the instruction runs
    // again at an address where the jump cache already has a full TB.
    write_in_two_tbs(&g_unwatched, 0, 0);
    write_in_two_tbs(&g_watched, 2, 1);

    s2e_make_symbolic(&sym, sizeof(sym), "sym");
    __asm__ __volatile__("movl $3, %[watched]\n"
                         ".globl after_klee_write\n"
                         "after_klee_write:\n"
                         "nop\n"
                         "nop\n"
                         : [watched] "=m"(g_watched)
                         : "d"(sym));

    _exit(0);
}

/// Resumes the child and checks that it stops on the breakpoint.
///
/// @param pid the child
/// @param expected the expected value of the watched variable
/// @param expected_pc the address of the instruction after the write
/// @return 0 on success, -1 on failure
static int expect_hit(pid_t pid, uint32_t expected, const char *expected_pc) {
    int status;

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        s2e_printf("FAILED: child did not trap, status %#x\n", status);
        return -1;
    }

    long dr6 = ptrace(PTRACE_PEEKUSER, pid, (void *) DEBUG_REG_OFFSET(6), NULL);
    if (!(dr6 & DR6_DR0_HIT)) {
        s2e_printf("FAILED: DR6 is %#lx\n", dr6);
        return -1;
    }
    ptrace(PTRACE_POKEUSER, pid, (void *) DEBUG_REG_OFFSET(6), NULL);

    uint32_t value = (uint32_t) ptrace(PTRACE_PEEKDATA, pid, (void *) &g_watched, NULL);
    if (value != expected) {
        s2e_printf("FAILED: watched value is %#x, expected %#x\n", value, expected);
        return -1;
    }

    unsigned long pc = (unsigned long) ptrace(PTRACE_PEEKUSER, pid, (void *) PC_OFFSET, NULL);
    if (pc != (unsigned long) expected_pc) {
        s2e_printf("FAILED: trapped at %#lx, expected %p\n", pc, expected_pc);
        return -1;
    }

    s2e_printf("passed: hit with value %#x\n", value);
    return 0;
}

int main(int argc, char **argv) {
    int status;
    pid_t pid = fork();

    if (pid == 0) {
        child();
    }

    waitpid(pid, &status, 0);

    if (ptrace(PTRACE_POKEUSER, pid, (void *) DEBUG_REG_OFFSET(0), (void *) &g_watched) < 0 ||
        ptrace(PTRACE_POKEUSER, pid, (void *) DEBUG_REG_OFFSET(7), (void *) DR7_VALUE) < 0) {
        s2e_printf("FAILED: could not set the debug registers\n");
        return 1;
    }

    if (expect_hit(pid, 1, after_native_write) < 0 || expect_hit(pid, 2, after_cached_write) < 0 ||
        expect_hit(pid, 3, after_klee_write) < 0) {
        kill(pid, SIGKILL);
        return 1;
    }

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        s2e_printf("All good\n");
    } else {
        s2e_printf("FAILED: child ended with status %#x\n", status);
    }

    return 0;
}
