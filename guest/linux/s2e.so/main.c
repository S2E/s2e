/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * Copyright (c) 2019, Cyberhaven
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

#define _GNU_SOURCE
#include <dlfcn.h>

#include <errno.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <s2e/monitors/linux.h>
#include <s2e/monitors/raw.h>
#include <s2e/s2e.h>

#include "function_models.h"
#include "modules.h"
#include "s2e_so.h"

#define MAX_S2E_SYM_ARGS_SIZE 44

#define s2e_printf printf

//
// global libc functions' declaration
//
uint8_t g_enable_function_models = 0;

static void __emit_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void initialize_cmdline(int argc, char **argv) {
    char *sym_args = getenv("S2E_SYM_ARGS");
    if (!sym_args) {
        s2e_warning("S2E_SYM_ARGS is not set. All arguments will be concrete");
        return;
    }

    char sym_arg_name[MAX_S2E_SYM_ARGS_SIZE];
    int i = 0;

    size_t str_args_len = strlen(sym_args);

    // 1 - symbolic, 0 - concrete
    char *args_type = (char *) calloc(argc, sizeof(char));
    if (!args_type) {
        __emit_error("Memory allocation failed");
    }

    int valid = 1;
    char *str_tmp = sym_args;
    while ((str_tmp - sym_args) < str_args_len) {
        char *end_ptr;
        long arg_num = strtol(str_tmp, &end_ptr, 10);
        if (end_ptr == str_tmp) {
            valid = 0;
            break;
        }

        if (arg_num >= 0 && arg_num < argc && errno != ERANGE) {
            // String could have same arg_num multiple times, so
            // use a bitmap instead of directly making value symbolic here.
            args_type[arg_num] = 1;
        } else {
            valid = 0;
        }

        str_tmp = end_ptr;
    }

    if (!valid) {
        s2e_warning("S2E_SYM_ARGS contains incorrect configuration\n");
    }

    for (i = 0; i < argc; i++) {
        if (args_type[i]) {
            snprintf(sym_arg_name, MAX_S2E_SYM_ARGS_SIZE, "arg%d", i);
            s2e_make_symbolic(argv[i], strlen(argv[i]), sym_arg_name);
        }
    }

    free(args_type);
}

//
// Overriding __libc_start_main
//

// The type of __libc_start_main
typedef int (*T_libc_start_main)(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void), void(*stack_end));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) __attribute__((noreturn));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) {
    initialize_models();
    s2e_load_modules_from_procmap();

    initialize_cmdline(argc, ubp_av);

    g_enable_function_models = s2e_plugin_loaded("FunctionModels");

    T_libc_start_main orig_libc_start_main = (T_libc_start_main) dlsym(RTLD_NEXT, "__libc_start_main");

    (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    exit(1); // This is never reached
}
