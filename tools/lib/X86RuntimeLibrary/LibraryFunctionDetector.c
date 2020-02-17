///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
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
///

#define _GNU_SOURCE 1

#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <BitcodeLibrary/Runtime.h>

#include "LibraryFunctionDetector.h"

static jmp_buf s_jmpbuf;
static sigset_t s_sigs, s_siga;
static uint8_t *s_stack;
static bool s_inside_function;

static const char *s_module_name;

static void schedule_alarm(int time_sec);

static uintptr_t s_faultaddr;
static uintptr_t s_faulteip;
static void segfault_handler(int sig, siginfo_t *si, ucontext_t *ucontext) {
    s_faultaddr = si->si_addr;
    s_faulteip = ucontext->uc_mcontext.gregs[REG_EIP];
    longjmp(s_jmpbuf, 1);
}

static void sigalrm_handler(int sig, siginfo_t *si, void *ptr) {
    if (!s_inside_function) {
        return;
    }

    longjmp(s_jmpbuf, 2);
}

/**
 * Reject all pointers that are not on the stack.
 * This is important so that the binary doesn't overwrite
 * our runtime.
 */
void __revgen_validate_pointer(uint64_t pointer) {
    if (((uint8_t *) pointer >= s_stack + STACK_SIZE) || (uint8_t *) pointer < s_stack) {
        printf("   Pointer %#" PRIx64 " not on the stack\n", pointer);
        dosegfault();
    }
}

typedef void (*detect_func_t)(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                              FILE *fp);

static detect_func_t s_detectors[] = {detect_strlen,
                                      detect_strcmp,
                                      detect_strtol,
                                      detect_output_str,
                                      detect_output_str_len,
                                      detect_output_fd_str,
                                      detect_output_fd_str_len,
                                      detect_output_fd_str_len_outlen,
                                      NULL};

static bool detect_function_type(revgen_function_t func, uint64_t func_addr, uint8_t *stack, FILE *fp) {
    /** setmp/longjmp requires volatile */
    volatile bool ret = false;
    printf("Detecting type of function %#p...\n", func_addr);

    fprintf(fp, "{\n");

    int detection_count = 0;

    for (unsigned i = 0; s_detectors[i]; ++i) {
        /**
         * The kernel doesn't get a chance to unblock SIGSEGV when we
         * longjump out of the signal handler. Do it here.
         * XXX: use sigsetjmp instead?
         */
        sigprocmask(SIG_UNBLOCK, &s_sigs, NULL);
        sigprocmask(SIG_UNBLOCK, &s_siga, NULL);

        int jret = setjmp(s_jmpbuf);
        if (jret == 1) {
            printf("  Function crashed at %p accessing %p\n", s_faulteip, s_faultaddr);
            s_inside_function = 0;
            schedule_alarm(0);
            if (ret) {
                detection_count++;
            }
            continue;
        } else if (jret == 2) {
            printf("  Function timedout\n");
            s_inside_function = 0;
            schedule_alarm(0);
            continue;
        }

        if (g_syscall_transmit_data) {
            free(g_syscall_transmit_data);
            g_syscall_transmit_data = NULL;
        }
        g_syscall_transmit_size = 0;

        ret = false;

        s_inside_function = 1;
        schedule_alarm(1);
        s_detectors[i](func, func_addr, stack, &ret, fp);
        schedule_alarm(0);
        s_inside_function = 0;

        if (ret) {
            detection_count++;
        }
    }

    fprintf(fp, "}\n");

    if (detection_count > 1) {
        printf("WARNING: DETECTED %d POSSIBLE MODELS FOR FUNCTION!\n");
    }

    return detection_count == 1;
}

/* Allocate an alternate stack for the signal handlers */
static void init_alternate_stack(void) {
    uint8_t *stk = (uint8_t *) malloc(SIGSTKSZ);
    if (!stk) {
        fprintf(stderr, "Could not allocate stack for signal handlers\n");
        exit(-1);
    }

    stack_t stack;
    stack.ss_flags = 0;
    stack.ss_size = SIGSTKSZ;
    stack.ss_sp = stk + stack.ss_size - 0x10;
    if (sigaltstack(&stack, NULL) < 0) {
        fprintf(stderr, "Could not register alternate stack for signals\n");
        exit(-1);
    }
}

/* Register segfault handler */
static void init_segfault_handler(void) {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_handler;

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        fprintf(stderr, "Error setting signal\n");
        exit(-1);
    }

    /* Setup mask */
    sigemptyset(&s_sigs);
    sigaddset(&s_sigs, SIGSEGV);
}

/* Register alarm handler */
static void init_alarm_handler(void) {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigalrm_handler;

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        fprintf(stderr, "Error setting signal\n");
        exit(-1);
    }

    /* Setup mask */
    sigemptyset(&s_siga);
    sigaddset(&s_siga, SIGALRM);
}

static void schedule_alarm(int time_sec) {
    struct itimerval timer = {0};
    timer.it_value.tv_sec = time_sec;
    timer.it_interval.tv_sec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
}

int __revgen_detect_library_functions __attribute__((weak));

struct func_and_addr {
    revgen_function_t f;
    uint64_t address;
};

int func_and_addr_cmp(const void *a, const void *b) {
    const struct func_and_addr *fa = (struct func_and_addr *) a;
    const struct func_and_addr *fb = (struct func_and_addr *) b;
    return fa->address - fb->address;
}

struct func_and_addr *get_revgen_functions(void) {
    struct func_and_addr *funcs = malloc(revgen_function_count * sizeof(struct func_and_addr));

    for (unsigned i = 0; i < revgen_function_count; ++i) {
        funcs[i].f = revgen_function_pointers[i];
        funcs[i].address = revgen_function_addresses[i];
    }

    qsort(funcs, revgen_function_count, sizeof(struct func_and_addr), func_and_addr_cmp);

    return funcs;
}

int __detect_library_functions(int argc, char **argv) {
    if (!__revgen_detect_library_functions) {
        return -1;
    }

    if (argc != 4) {
        printf("Usage: %s plugin_var_name module_name output_file\n", argv[0]);
        exit(-1);
    }

    const char *plugin_var_name = argv[1];
    s_module_name = argv[2];
    const char *output_file = argv[3];

    FILE *fp = fopen(output_file, "a+");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", output_file);
        exit(-1);
    }

    s_stack = (uint8_t *) mmap((void *) NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (s_stack == MAP_FAILED) {
        fprintf(stderr, "Could not mmap memory for stack\n");
        exit(-1);
    }

    printf("Allocated stack at %p\n", s_stack);

    /**
     * Calling arbitrary functions with wrong inputs may cause crashes.
     * Make sure we catch them in the signal handler.
     */
    init_alternate_stack();
    init_segfault_handler();
    init_alarm_handler();

    fprintf(fp, "%s[\"%s\"] = {}\n", plugin_var_name, s_module_name);

    fflush(fp);
    long last_pos = ftello(fp);

    struct func_and_addr *funcs = get_revgen_functions();

    for (unsigned i = 0; i < revgen_function_count; ++i) {
        fprintf(fp, "%s[\"%s\"][%#llx] = ", plugin_var_name, s_module_name, funcs[i].address);
        bool ret = detect_function_type(funcs[i].f, funcs[i].address, s_stack, fp);
        fprintf(fp, "\n");

        if (!ret) {
            fflush(fp);
            if (ftruncate(fileno(fp), last_pos) < 0) {
                fprintf(stderr, "Could not truncate file\n");
                exit(-1);
            }
            fseek(fp, last_pos, SEEK_SET);
        } else {
            printf("ret=%d\n", ret);
            fflush(fp);
            last_pos = ftello(fp);
        }
    }

    free(funcs);

    munmap(s_stack, STACK_SIZE);
    fclose(fp);

    printf("Done function detection\n");
    return 0;
}
