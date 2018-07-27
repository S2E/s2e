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

#define _GNU_SOURCE
#include <dlfcn.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>

#include <s2e/monitors/linux.h>
#include <s2e/monitors/raw.h>
#include <s2e/s2e.h>

#include "function_models.h"
#include "s2e_so.h"

#define MAX_S2E_SYM_ARGS_SIZE 44

// ***********************************
// global libc functions' declaration
// ***********************************
uint8_t g_enable_function_models = 0;

static void __emit_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// Returns the base name (without directory) of a path
static const char *__base_name(const char *path) {
    const char *lastSlash = strrchr(path, '/');
    if (lastSlash != NULL) {
        return lastSlash + 1; // The character after the slash
    }
    return path;
}

// Describes an executable portion of the address space
typedef struct _procmap_entry_t {
    uintptr_t base;
    uintptr_t limit;
    const char *name;
} procmap_entry_t;

static inline int read_procmap_entry(char *line, uintptr_t *base, uintptr_t *limit, unsigned *inode, char *path) {
    return sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %*c%*c%*c%*c %*x %*s %d %127[^\n]", base, limit, inode, path);
}

//
// Returns each module listed in /proc/self/maps as an array of entries. The last entry is NULL.
//
// Each row in /proc/self/maps describes a region of contiguous virtual memory in a process's address space. An example
// of a /proc/self/maps listing is given below:
//
// address                    perms  offset    dev    inode    path
// 00400000-0040c000          r-xp   00000000  08:01  3671038  /bin/cat
// 0060b000-0060c000          r--p   0000b000  08:01  3671038  /bin/cat
// 0060c000-0060d000          rw-p   0000c000  08:01  3671038  /bin/cat
// 017d4000-017f5000          rw-p   00000000  00:00  0        [heap]
// 7f3c75827000-7f3c75aff000  r--p   00000000  08:01  2097928  /usr/lib/locale/locale-archive
// 7f3c75aff000-7f3c75cbf000  r-xp   00000000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75cbf000-7f3c75ebf000  ---p   001c0000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75ebf000-7f3c75ec3000  r--p   001c0000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75ec3000-7f3c75ec5000  rw-p   001c4000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
//
// Where:
//   address - start and end address of the memory region in the process's address space
//   perms   - read write execute private/shared permissions
//   offset  - file offset from where the memory region was mapped
//   dev     - major:minor device identifier
//   inode   - file number
//   path    - file path
//
// The inode field is used to uniquely identify modules in the map. Only non-zero inode values are considered. The
// inode value is checked while iterating over each row in the map. While this inode value remains the same, the
// `limit` address of the current `procmap_entry_t` is set to the maximum end address. When the inode changes, a new
// `procmap_entry_t` is added to the module map.
//
// This assumes that the different memory regions of a module are contiguous in memory. As we can see in the above
// example, this is not necessarily true - the executable region of /bin/cat ends at 0x40c000, while the next section
// (read-only data) starts at 0x60b000. However, this is a good enough approximation for now.
//
static procmap_entry_t *load_process_map(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return NULL;
    }

    int matches;
    char line[256], path[128];
    procmap_entry_t *result = NULL;
    procmap_entry_t current_entry;
    unsigned nb_entries = 0;

    uintptr_t start_addr, end_addr;
    unsigned current_inode = 0, previous_inode = 0;

    // Read /proc/self/maps until we can initialize previous_inode to a non-zero inode, then initialize the first
    // proc map entry
    do {
        if (!fgets(line, sizeof(line), maps)) {
            goto end;
        }

        matches = read_procmap_entry(line, &current_entry.base, &current_entry.limit, &previous_inode, path);
        if (matches != 4) {
            continue;
        }

        current_entry.name = strdup(path);
    } while (previous_inode == 0);

    // Read the other proc map entries
    while (fgets(line, sizeof(line), maps)) {
        matches = read_procmap_entry(line, &start_addr, &end_addr, &current_inode, path);
        if (matches != 4) {
            continue;
        }

        if (current_inode == previous_inode && end_addr > current_entry.limit) {
            current_entry.limit = end_addr;
        } else if (current_inode != 0 && current_inode != previous_inode) {
            // Save the previous proc map entry
            ++nb_entries;
            result = realloc(result, sizeof(*result) * nb_entries);
            result[nb_entries - 1] = current_entry;

            // Start a new proc map entry
            current_entry.base = start_addr;
            current_entry.limit = end_addr;
            current_entry.name = strdup(path);

            previous_inode = current_inode;
        }
    }

    // Save the final proc map entry
    if (current_inode != previous_inode) {
        ++nb_entries;
        result = realloc(result, sizeof(*result) * nb_entries);
        result[nb_entries - 1] = current_entry;
    }

end:
    fclose(maps);

    // Add the NULL entry
    current_entry.base = current_entry.limit = 0;
    current_entry.name = NULL;

    ++nb_entries;
    result = realloc(result, sizeof(*result) * nb_entries);
    result[nb_entries - 1] = current_entry;

    return result;
}

static void display_process_map(procmap_entry_t *map) {
    s2e_printf("Process map:\n");
    while (map->base && map->limit) {
        s2e_printf("Base=0x%" PRIxPTR " Limit=0x%" PRIxPTR " Name=%s\n", map->base, map->limit, map->name);
        ++map;
    }
}

static void register_modules(procmap_entry_t *map) {
    if (s2e_plugin_loaded("RawMonitor")) {
        while (map->base && map->limit) {
            struct S2E_RAWMON_COMMAND_MODULE_LOAD m = {0};

            m.name = (uintptr_t) __base_name(map->name);
            m.path = (uintptr_t) map->name;
            m.pid = getpid();
            m.load_base = map->base;
            m.size = map->limit - map->base;
            m.entry_point = 0;
            m.native_base = 0;
            m.kernel_mode = 0;

            s2e_raw_load_module(&m);
            ++map;
        }
    } else if (s2e_plugin_loaded("LinuxMonitor")) {
        while (map->base && map->limit) {
            struct S2E_LINUXMON_COMMAND_MODULE_LOAD m = {0};

            m.load_base = map->base;
            m.size = map->limit - map->base;
            m.start_code = 0;
            m.end_code = 0;
            m.start_data = 0;
            m.end_data = 0;
            m.module_path = (uint64_t) map->name;

            s2e_linux_load_module(getpid(), &m);
            ++map;
        }
    }
}

static void initialize_modules() {
    // Load the process map and get the info about the current process
    procmap_entry_t *proc_map = load_process_map();
    display_process_map(proc_map);
    register_modules(proc_map);
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

    // 1 - concolic; 0 - concrete
    char *args_type = (char *) calloc(argc, sizeof(char));
    if (!args_type) {
        __emit_error("Memory allocation failed");
    }
    memset(args_type, 0, argc);

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
            // use a bitmap instead of directly making value concolic here.
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
            s2e_make_concolic(argv[i], strlen(argv[i]), sym_arg_name);
        }
    }

    free(args_type);
}

// ****************************
// Overriding __libc_start_main
// ****************************

// The type of __libc_start_main
typedef int (*T_libc_start_main)(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void), void(*stack_end));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) __attribute__((noreturn));

int __libc_start_main(int *(main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void), void *stack_end) {
    initialize_models();
    initialize_modules();

    initialize_cmdline(argc, ubp_av);

    g_enable_function_models = s2e_plugin_loaded("FunctionModels");

    T_libc_start_main orig_libc_start_main = (T_libc_start_main) dlsym(RTLD_NEXT, "__libc_start_main");

    (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    exit(1); // This is never reached
}
