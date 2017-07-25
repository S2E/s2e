/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
/// Copyright (c) 2017 Dependable Systems Lab, EPFL
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

#ifndef S2E_LINUX_COMMANDS_H
#define S2E_LINUX_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#define S2E_LINUXMON_COMMAND_VERSION 0x201701101602ULL // date +%Y%m%d%H%M

enum S2E_LINUXMON_COMMANDS {
    LINUX_SEGFAULT,
    LINUX_PROCESS_LOAD,
    LINUX_MODULE_LOAD,
    LINUX_TRAP,
    LINUX_PROCESS_EXIT,
    LINUX_INIT,
};

struct S2E_LINUXMON_COMMAND_PROCESS_LOAD {
    uint64_t process_id;
    uint64_t entry_point;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t start_stack;
    char process_path[128]; // not NULL terminated
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_MODULE_LOAD {
    uint64_t load_base;
    uint64_t size;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    char module_path[128]; // not NULL terminated
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_SEG_FAULT {
    uint64_t pc;
    uint64_t address;
    uint64_t fault;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_TRAP {
    uint64_t pc;
    int trapnr;
    int signr;
    long error_code;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_PROCESS_EXIT {
    uint64_t code;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_INIT {
    uint64_t page_offset;
    uint64_t current_task_address;
    uint64_t task_struct_pid_offset;
    uint64_t task_struct_tgid_offset;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND {
    uint64_t version;
    enum S2E_LINUXMON_COMMANDS Command;
    uint64_t currentPid;
    union {
        struct S2E_LINUXMON_COMMAND_PROCESS_LOAD ProcessLoad;
        struct S2E_LINUXMON_COMMAND_MODULE_LOAD ModuleLoad;
        struct S2E_LINUXMON_COMMAND_SEG_FAULT SegFault;
        struct S2E_LINUXMON_COMMAND_TRAP Trap;
        struct S2E_LINUXMON_COMMAND_PROCESS_EXIT ProcessExit;
        struct S2E_LINUXMON_COMMAND_INIT Init;
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
