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

typedef int (*cmd_handler_t)(const char **args);

typedef struct _cmd_t {
    char *name;
    cmd_handler_t handler;
    unsigned args_count;
    char *description;
} cmd_t;

static int handler_register_module(const char **args) {
    const char *name = args[0];
    const char *path = args[1];
    uint64_t base = strtoul(args[2], NULL, 0);
    uint64_t size = strtoul(args[3], NULL, 0);
    uint64_t entry_point = strtoul(args[4], NULL, 0);
    uint64_t native_base = strtoul(args[5], NULL, 0);
    uint64_t kernel_mode = strtoul(args[6], NULL, 0);
    uint64_t pid = strtoul(args[7], NULL, 0);

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

static int handler_kill(const char **args) {
    int status = atoi(args[0]);
    const char *message = args[1];
    s2e_kill_state(status, message);
    return 0;
}

static int handler_message(const char **args) {
    s2e_message(args[0]);
    return 0;
}

static int handler_check(const char **args) {
    // Return 0 if we are running in S2E mode, or 1 otherwise
    return s2e_check() == 0 ? 1 : 0;
}

static int handler_wait(const char **args) {
    s2e_message("Waiting for S2E...");
    while (!s2e_check()) {
        SLEEP(1);
    }
    s2e_message("Done waiting for S2E.");
    return 0;
}

static int handler_symbwrite(const char **args) {
    int n_bytes = -1;
    int i;

    n_bytes = atoi(args[0]);
    if (n_bytes < 0) {
        fprintf(stderr, "number of bytes may not be negative\n");
        return -1;
    } else if (n_bytes == 0) {
        return -2;
    }

    char *buffer = calloc(1, n_bytes + 1);
    s2e_make_symbolic(buffer, n_bytes, "buffer");

    for (i = 0; i < n_bytes; ++i) {
        putchar(buffer[i]);
    }

    free(buffer);

    return 0;
}

static int handler_symbwrite_dec(const char **args) {
    int n_bytes = -1;
    int i;

    n_bytes = atoi(args[0]);
    if (n_bytes < 0) {
        fprintf(stderr, "number of bytes may not be negative\n");
        return -1;
    } else if (n_bytes == 0) {
        return -1;
    }

    char *buffer = calloc(1, n_bytes + 1);
    memset(buffer, '0', n_bytes);
    s2e_make_concolic(buffer, n_bytes, "buffer");

    for (i = 0; i < n_bytes; ++i) {
        s2e_assume_range(buffer[i], '0', '9');
        putchar(buffer[i]);
    }

    free(buffer);

    return 0;
}

static int handler_symbfile(const char **args) {
    const char *filename = args[0];
    int flags = O_RDWR;

#ifdef _WIN32
    flags |= O_BINARY;
#endif

    int fd = open(filename, flags);
    if (fd < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not open %s\n", filename);
        return -1;
    }

    /* Determine the size of the file */
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not determine the size of %s\n", filename);
        return -2;
    }

    char buffer[0x1000];

    unsigned current_chunk = 0;
    unsigned total_chunks = size / sizeof(buffer);
    if (size % sizeof(buffer)) {
        ++total_chunks;
    }

    /**
     * Replace special characters in the filename with underscores.
     * It should make it easier for plugins to generate
     * concrete files, while preserving info about the original path
     * and without having to deal with the slashes.
     **/
    char cleaned_name[512];
    strncpy(cleaned_name, filename, sizeof(cleaned_name));
    for (unsigned i = 0; cleaned_name[i]; ++i) {
        if (!isalnum(cleaned_name[i])) {
            cleaned_name[i] = '_';
        }
    }

    off_t offset = 0;
    do {
        /* Read the file in chunks of 4K and make them concolic */
        char symbvarname[512];

        if (lseek(fd, offset, SEEK_SET) < 0) {
            s2e_kill_state_printf(-1, "symbfile: could not seek to position %d", offset);
            return -3;
        }

        ssize_t totransfer = size > sizeof(buffer) ? sizeof(buffer) : size;

        /* Read the data */
        ssize_t read_count = read(fd, buffer, totransfer);
        if (read_count < 0) {
            s2e_kill_state_printf(-1, "symbfile: could not read from file %s", filename);
            return -4;
        }

        /**
         * Make the buffer concolic.
         * The symbolic variable name encodes the original file name with its path
         * as well as the chunk id contained in the buffer.
         * A test case generator should therefore be able to reconstruct concrete
         * files easily.
         */
        snprintf(symbvarname, sizeof(symbvarname), "__symfile___%s___%d_%d_symfile__", cleaned_name, current_chunk,
                 total_chunks);
        s2e_make_concolic(buffer, read_count, symbvarname);

        /* Write it back */
        if (lseek(fd, offset, SEEK_SET) < 0) {
            s2e_kill_state_printf(-1, "symbfile: could not seek to position %d", offset);
            return -5;
        }

        ssize_t written_count = write(fd, buffer, read_count);
        if (written_count < 0) {
            s2e_kill_state_printf(-1, "symbfile: could not write to file %s", filename);
            return -6;
        }

        if (read_count != written_count) {
            /* XXX: should probably retry...*/
            s2e_kill_state_printf(-1, "symbfile: could not write the read amount");
            return -7;
        }

        offset += read_count;
        size -= read_count;
        ++current_chunk;

    } while (size > 0);

    close(fd);
    return 0;
}

static int handler_exemplify(const char **args) {
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
static int handler_launch(const char **args) {
    const char *prog = args[0];
    const char *message = args[1];
    int ret = system(prog);
    s2e_kill_state(0, message);
    return ret; // Doesn't matter...
}

static int handler_fork(const char **args) {
    if (!strcmp(args[0], "disable") || !strcmp(args[0], "0")) {
        s2e_disable_forking();
    } else {
        s2e_enable_forking();
    }

    return 0;
}

static int handler_pathid(const char **args) {
    printf("%u\n", s2e_get_path_id());
    return 0;
}

static int handler_yield(const char **args) {
    s2e_yield();
    return 0;
}

static int handler_invoke(const char **args) {
    const char *plugin = args[0];
    const char *value = args[1];

    return s2e_invoke_plugin(plugin, (void *) value, strlen(value) + 1);
}

static int handler_get_seed_file(const char **args) {
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

static int handler_seedsearcher_enable(const char **args) {
    s2e_seed_searcher_enable();
    return 0;
}

#define COMMAND(c, args, desc) \
    { #c, handler_##c, args, desc }

static cmd_t s_commands[] = {
    COMMAND(kill, 2, "Kill the current state with the specified numeric status and message"),
    COMMAND(message, 1, "Display a message"),
    COMMAND(check, 0, "Check if we are in S2E mode"),
    COMMAND(wait, 0, "Wait for S2E mode"),
    COMMAND(yield, 0, "Yield the current state"),
    COMMAND(symbwrite, 1, "Write n symbolic bytes to stdout"),
    COMMAND(symbwrite_dec, 1, "Write n symbolic decimal digits to stdout"),
    COMMAND(symbfile, 1, "Makes the specified file concolic. The file should be stored in a ramdisk."),
    COMMAND(exemplify, 0, "Read from stdin and write an example to stdout"),
    COMMAND(launch, 2,
            "Launch the specified program or script, then kill the state with the specified message when done."),
    COMMAND(fork, 1, "Enable/disable forking"),
    COMMAND(pathid, 0, "Print path id"),
    COMMAND(invoke, 2, "Invoke a plugin with a value"),
    COMMAND(register_module, 8, "params: name path loadbase size entrypoint nativebase kernelmode pid"),
    COMMAND(get_seed_file, 0, "Returns the name of the currently available seed file"),
    COMMAND(seedsearcher_enable, 0, "Activates the seed searcher"),
    {NULL, NULL, 0, NULL}};

static void print_commands(void) {
    unsigned i = 0;
    printf("%-15s  %s %s\n\n", "Command name", "Argument count", "Description");
    while (s_commands[i].handler) {
        printf("%-15s  %d              %s\n", s_commands[i].name, s_commands[i].args_count, s_commands[i].description);
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
    int retval = -1;
    if (argc < 2) {
        print_commands();
        goto err;
    }

    const char *cmd = argv[1];
    int cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        fprintf(stderr, "Command %s not found\n", cmd);
        goto err;
    }

    argc -= 2;
    ++argv;
    ++argv;

    if (argc != s_commands[cmd_index].args_count) {
        fprintf(stderr, "Invalid number of arguments supplied (received %d, expected %d)\n", argc,
                s_commands[cmd_index].args_count);
        goto err;
    }

    retval = s_commands[cmd_index].handler(argv);

err:
    // On Windows msys bash, a negative value returned from main will appear as 0.
    // Negate it here to avoid losing it.
    if (retval < 0) {
        retval = -retval;
    }

    return retval;
}
