/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
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

#include <s2e/monitors/raw.h>
#include <s2e/s2e.h>
#include <s2e/seed_searcher.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP(x) Sleep((x) *1000)
#else
#define SLEEP(x) sleep(x)
#endif

typedef int (*cmd_handler_t)(int argc, const char **args);

typedef struct _cmd_t {
    const char *name;
    cmd_handler_t handler;
    unsigned min_args_count;
    unsigned max_args_count;
    const char *description;
} cmd_t;

int handler_symbfile(int argc, const char **args);

static int handler_register_module(int argc, const char **args) {
    const char *name = args[0];
    const char *path = args[1];
    uint64_t base = strtoul(args[2], nullptr, 0);
    uint64_t size = strtoul(args[3], nullptr, 0);
    uint64_t entry_point = strtoul(args[4], nullptr, 0);
    uint64_t native_base = strtoul(args[5], nullptr, 0);
    uint64_t kernel_mode = strtoul(args[6], nullptr, 0);
    uint64_t pid = strtoul(args[7], nullptr, 0);

    struct S2E_RAWMON_COMMAND_MODULE_LOAD m;
    m.name = (uintptr_t) name;
    m.path = (uintptr_t) path;
    m.pid = pid;
    m.load_base = base;
    m.size = size;
    m.entry_point = entry_point;
    m.native_base = native_base;
    m.kernel_mode = kernel_mode;

    s2e_raw_load_module(&m);
    return 0;
}

static int handler_kill(int argc, const char **args) {
    int status = atoi(args[0]);
    const char *message = args[1];
    s2e_kill_state(status, message);
    return 0;
}

static int handler_message(int argc, const char **args) {
    s2e_message(args[0]);
    return 0;
}

static int handler_check(int argc, const char **args) {
    // Return 0 if we are running in S2E mode, or 1 otherwise
    return s2e_check() == 0 ? 1 : 0;
}

static int handler_wait(int argc, const char **args) {
    s2e_message("Waiting for S2E...");
    while (!s2e_check()) {
        SLEEP(1);
    }
    s2e_message("Done waiting for S2E.");
    return 0;
}

static int handler_symbwrite(int argc, const char **args) {
    int n_bytes = -1;
    int i;

    n_bytes = atoi(args[0]);
    if (n_bytes < 0) {
        fprintf(stderr, "number of bytes may not be negative\n");
        return -1;
    } else if (n_bytes == 0) {
        return -2;
    }

    char *buffer = (char *) calloc(1, n_bytes + 1);
    s2e_make_symbolic(buffer, n_bytes, "buffer");

    for (i = 0; i < n_bytes; ++i) {
        putchar(buffer[i]);
    }

    free(buffer);

    return 0;
}

static int handler_symbwrite_dec(int argc, const char **args) {
    int n_bytes = -1;
    int i;

    n_bytes = atoi(args[0]);
    if (n_bytes < 0) {
        fprintf(stderr, "number of bytes may not be negative\n");
        return -1;
    } else if (n_bytes == 0) {
        return -1;
    }

    char *buffer = (char *) calloc(1, n_bytes + 1);
    memset(buffer, '0', n_bytes);
    s2e_make_concolic(buffer, n_bytes, "buffer");

    for (i = 0; i < n_bytes; ++i) {
        s2e_assume_range(buffer[i], '0', '9');
        putchar(buffer[i]);
    }

    free(buffer);

    return 0;
}

static int handler_exemplify(int argc, const char **args) {
#define BUF_SIZE 32
    char buffer[BUF_SIZE] = {0};
    unsigned int i;

    while (fgets(buffer, sizeof(buffer), stdin)) {
        for (i = 0; i < BUF_SIZE; ++i) {
            if (s2e_is_symbolic(&buffer[i], sizeof(buffer[i]))) {
                s2e_get_example(&buffer[i], sizeof(buffer[i]));
            }
        }

        fputs(buffer, stdout);
        memset(buffer, 0, sizeof(buffer));
    }

    return 0;
}

/**
 * This can be used when calling s2ecmd kill does not work.
 * That could happen when the system becomes very unstable,
 * e.g., if symbex trashes the filesystem during testing and
 * the OS can't read files anymore.
 */
static int handler_launch(int argc, const char **args) {
    const char *prog = args[0];
    const char *message = args[1];
    int ret = system(prog);
    s2e_kill_state(0, message);
    return ret; // Doesn't matter...
}

static int handler_fork(int argc, const char **args) {
    if (!strcmp(args[0], "disable") || !strcmp(args[0], "0")) {
        s2e_disable_forking();
    } else {
        s2e_enable_forking();
    }

    return 0;
}

static int handler_pathid(int argc, const char **args) {
    printf("%u\n", s2e_get_path_id());
    return 0;
}

static int handler_yield(int argc, const char **args) {
    s2e_yield();
    return 0;
}

static int handler_invoke(int argc, const char **args) {
    const char *plugin = args[0];
    const char *value = args[1];

    return s2e_invoke_plugin(plugin, (void *) value, strlen(value) + 1);
}

static int handler_get_seed_file(int argc, const char **args) {
    unsigned path_id = s2e_get_path_id();
    if (path_id != 0) {
        s2e_kill_state(-1, "s2ecmd: wrong state for getting seed file");
    }

    /* Get the seed file, if there is one */
    char seed_file[256] = {0};
    int should_fork = 0;
    int ret = s2e_seed_get_file(seed_file, sizeof(seed_file), &should_fork);
    s2e_printf("s2e_seed_get_file: ret=%d should_fork=%d seed_file=%s\n", ret, should_fork, seed_file);

    if (should_fork) {
        /* Fork a new state that will handle the seed */
        int fk = 0;
        s2e_make_concolic(&fk, sizeof(fk), "seed_fork");

        if (fk == 0) {
            /* State 0 is always reserved for getting next seed, if available */
            path_id = s2e_get_path_id();
            if (path_id != 0) {
                s2e_kill_state(-1, "s2ecmd: wrong state after forking");
            }
        } else {

            if (ret < 0) {
                s2e_message("Exploring without seed inputs");
                return 0;
            } else {
                s2e_message("Exploring using seed inputs");
                printf("%s", seed_file);
                return 0;
            }
        }
    }

    /* Keep looping */
    s2e_message("Going to next seed loop iteration");
    return -1;
}

static int handler_seedsearcher_enable(int argc, const char **args) {
    s2e_seed_searcher_enable();
    return 0;
}

static int handler_flush_tbs(int argc, const char **args) {
    s2e_flush_tbs();
    return 0;
}

#define COMMAND(c, arg_count, desc) \
    { #c, handler_##c, arg_count, arg_count, desc }

#define COMMAND2(c, min_arg_count, max_arg_count, desc) \
    { #c, handler_##c, min_arg_count, max_arg_count, desc }

static cmd_t s_commands[] = {
    COMMAND(kill, 2, "Kill the current state with the specified numeric status and message"),
    COMMAND(message, 1, "Display a message"),
    COMMAND(check, 0, "Check if we are in S2E mode"),
    COMMAND(wait, 0, "Wait for S2E mode"),
    COMMAND(yield, 0, "Yield the current state"),
    COMMAND(symbwrite, 1, "Write n symbolic bytes to stdout"),
    COMMAND(symbwrite_dec, 1, "Write n symbolic decimal digits to stdout"),
    COMMAND2(symbfile, 1, 2, "Makes the specified file concolic. The file should be stored in a ramdisk. File name may "
                             "be preceded by block size."),
    COMMAND(exemplify, 0, "Read from stdin and write an example to stdout"),
    COMMAND(launch, 2,
            "Launch the specified program or script, then kill the state with the specified message when done."),
    COMMAND(fork, 1, "Enable/disable forking"),
    COMMAND(pathid, 0, "Print path id"),
    COMMAND(invoke, 2, "Invoke a plugin with a value"),
    COMMAND(register_module, 8, "params: name path loadbase size entrypoint nativebase kernelmode pid"),
    COMMAND(get_seed_file, 0, "Returns the name of the currently available seed file"),
    COMMAND(seedsearcher_enable, 0, "Activates the seed searcher"),
    COMMAND(flush_tbs, 0, "Flush the translation block cache"),
    {nullptr, nullptr, 0, 0, nullptr}};

static void print_commands(void) {
    unsigned i = 0;
    printf("%-15s  %s %s\n\n", "Command name", "Argument count", "Description");
    while (s_commands[i].handler) {
        printf("%-15s  %d              %s\n", s_commands[i].name, s_commands[i].min_args_count,
               s_commands[i].description);
        ++i;
    }
}

static int find_command(const char *cmd) {
    unsigned i = 0;
    while (s_commands[i].handler) {
        if (!strcmp(s_commands[i].name, cmd)) {
            return i;
        }
        ++i;
    }
    return -1;
}

int main(int argc, const char **argv) {
    const char *cmd = nullptr;
    int cmd_index = 0;
    int retval = -1;

    unsigned min_args, max_args;

    if (argc < 2) {
        print_commands();
        goto err;
    }

    cmd = argv[1];
    cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        fprintf(stderr, "Command %s not found\n", cmd);
        goto err;
    }

    argc -= 2;
    ++argv;
    ++argv;

    min_args = s_commands[cmd_index].min_args_count;
    max_args = s_commands[cmd_index].max_args_count;

    if (!(argc >= min_args && argc <= max_args)) {
        fprintf(stderr, "Invalid number of arguments supplied (received %d, expected %d)\n", argc,
                s_commands[cmd_index].min_args_count);
        goto err;
    }

    retval = s_commands[cmd_index].handler(argc, argv);

err:
    // On Windows msys bash, a negative value returned from main will appear as 0.
    // Negate it here to avoid losing it.
    if (retval < 0) {
        retval = -retval;
    }

    return retval;
}
