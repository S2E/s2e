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

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S2E_LINUXMON_COMMAND_VERSION 0x201903212249ULL // date +%Y%m%d%H%M

enum S2E_LINUXMON_COMMANDS {
    LINUX_SEGFAULT,
    LINUX_PROCESS_LOAD,
    LINUX_MODULE_LOAD,
    LINUX_TRAP,
    LINUX_PROCESS_EXIT,
    LINUX_INIT,
    LINUX_KERNEL_PANIC,
    LINUX_MEMORY_MAP,
    LINUX_MEMORY_UNMAP,
    LINUX_MEMORY_PROTECT
};

struct S2E_LINUXMON_COMMAND_MEMORY_MAP {
    uint64_t address;
    uint64_t size;
    uint64_t prot;
    uint64_t flag;
    uint64_t pgoff;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_MEMORY_UNMAP {
    uint64_t start;
    uint64_t end;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_MEMORY_PROTECT {
    uint64_t start;
    uint64_t size;
    uint64_t prot;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_PROCESS_LOAD {
    // Zero-terminated path to process
    uint64_t process_path;
} __attribute__((packed));

struct S2E_LINUXMON_PHDR_DESC {
    uint64_t index;
    uint64_t vma;

    // Copy of the program header contents
    uint64_t p_type;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_flags;
    uint64_t p_align;

    struct S2E_LINUXMON_COMMAND_MEMORY_MAP mmap;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_MODULE_LOAD {
    uint64_t module_path;
    uint64_t entry_point;
    uint64_t phdr;
    uint64_t phdr_size;
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
    uint64_t start_kernel;
    uint64_t current_task_address;
    uint64_t task_struct_pid_offset;
    uint64_t task_struct_tgid_offset;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_KERNEL_PANIC {
    uint64_t message;
    uint64_t message_size;
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
        struct S2E_LINUXMON_COMMAND_KERNEL_PANIC Panic;
        struct S2E_LINUXMON_COMMAND_MEMORY_MAP MemMap;
        struct S2E_LINUXMON_COMMAND_MEMORY_UNMAP MemUnmap;
        struct S2E_LINUXMON_COMMAND_MEMORY_PROTECT MemProtect;
    };
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
