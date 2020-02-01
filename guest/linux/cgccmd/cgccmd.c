/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2016 Cyberhaven
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

#include <s2e/cgc_interface.h>
#include <s2e/monitors/commands/decree.h>
#include <s2e/s2e.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*cmd_handler_t)(const char **args);

typedef struct _cmd_t {
    char *name;
    cmd_handler_t handler;
    unsigned args_count;
    char *description;
} cmd_t;

static int handler_concolic(const char **args) {
    struct S2E_DECREEMON_COMMAND cmd = {0};

    cmd.version = S2E_DECREEMON_COMMAND_VERSION;
    cmd.currentPid = getpid();
    strncpy(cmd.currentName, "cgccmd", sizeof(cmd.currentName));

    int enable = !strcmp(args[0], "on");
    if (enable) {
        cmd.Command = DECREE_CONCOLIC_ON;
    } else {
        cmd.Command = DECREE_CONCOLIC_OFF;
    }

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    int ret = s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    return ret;
}

static int handler_set_seed_id(const char **args) {
    struct S2E_CGCINT_COMMAND cmd = {0};
    cmd.Command = CGCINT_SET_SEED_ID;
    cmd.SeedId = strtoll(args[0], NULL, 10);

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    int ret = s2e_invoke_plugin("CGCInterface", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    return ret;
}

#define COMMAND(c, args, desc) \
    { #c, handler_##c, args, desc }

static cmd_t s_commands[] = {COMMAND(concolic, 1,
                                     "Turns on/off concolic execution on the current path "
                                     "(cb-test specific)"),
                             COMMAND(set_seed_id, 1, "Sets the seed id for the current path"),
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
    if (argc < 2) {
        print_commands();
        return -1;
    }

    const char *cmd = argv[1];
    int cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        printf("Command %s not found\n", cmd);
        return -1;
    }

    argc -= 2;
    ++argv;
    ++argv;

    if (argc != s_commands[cmd_index].args_count) {
        printf("Invalid number of arguments supplied (received %d, expected %d)\n", argc,
               s_commands[cmd_index].args_count);
        return -1;
    }

    return s_commands[cmd_index].handler(argv);
}
