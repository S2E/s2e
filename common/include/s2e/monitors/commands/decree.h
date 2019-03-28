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

#ifndef S2E_DECREE_COMMANDS_H
#define S2E_DECREE_COMMANDS_H

#include "linux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define S2E_DECREEMON_COMMAND_VERSION 0x201903202239ULL // date +%Y%m%d%H%M

enum S2E_DECREEMON_COMMANDS {
    DECREE_SEGFAULT,
    DECREE_PROCESS_LOAD,
    DECREE_READ_DATA,
    DECREE_WRITE_DATA,
    DECREE_FD_WAIT,
    DECREE_RANDOM,
    DECREE_READ_DATA_POST,
    DECREE_CONCOLIC_ON,
    DECREE_CONCOLIC_OFF,
    DECREE_GET_CFG_BOOL,
    DECREE_HANDLE_SYMBOLIC_ALLOCATE_SIZE,
    DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER,
    DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER,
    DECREE_HANDLE_SYMBOLIC_RANDOM_BUFFER,
    DECREE_COPY_TO_USER,
    DECREE_UPDATE_MEMORY_MAP,
    DECREE_SET_CB_PARAMS,
    DECREE_INIT,
    DECREE_KERNEL_PANIC,
    DECREE_MODULE_LOAD,
};

struct S2E_DECREEMON_COMMAND_READ_DATA {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size;
    uint64_t size_expr_addr;
    uint64_t result_addr;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_READ_DATA_POST {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_WRITE_DATA {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size_addr;
    uint64_t size_expr_addr;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_FD_WAIT {
    uint64_t tv_sec;
    uint64_t tv_nsec;
    uint64_t has_timeout;
    uint64_t nfds;
    uint64_t invoke_orig;
    int64_t result;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_SEG_FAULT {
    uint64_t pc;
    uint64_t address;
    uint64_t fault;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_RANDOM {
    uint64_t buffer;
    uint64_t buffer_size;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_GET_CFG_BOOL {
    uint64_t key_addr;
    uint64_t value;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_SIZE {
    uint64_t size_addr;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER {
    uint64_t ptr_addr;
    uint64_t size_addr;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_COPY_TO_USER {
    uint64_t user_addr;
    uint64_t addr;
    uint64_t count;
    uint64_t done;
    uint64_t ret;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_UPDATE_MEMORY_MAP {
    uint64_t count;
    uint64_t buffer;
} __attribute__((packed));

#define S2E_DECREEMON_MAX_SEED_SIZE 64
#define S2E_DECREEMON_DECREE_SEED_SIZE 48

struct S2E_DECREEMON_COMMAND_SET_CB_PARAMS {
    int64_t cgc_max_transmit;
    int64_t cgc_max_receive;
    int64_t skip_rng_count;

    /// \brief Guest pointer to the full seed.
    ///
    /// This pointer is null in case no seed has been
    /// passed to the CB as a command line argument.
    /// Plugin code should not write to this pointer,
    /// and instead use cgc_seed if it wants to modify
    /// the existing seed or create a new one.
    uint64_t cgc_seed_ptr;

    /// \brief In/out length of the seed
    ///
    /// The guest sets this value to the size of the existing
    /// seed. Plugin code may overwrite it with the size of
    /// the new seed, or set it to zero in case the existing
    /// seed should be used.
    int64_t cgc_seed_len;

    /// \brief Output buffer that stores a new rng seed.
    ///
    /// Plugin code may write a new seed to this buffer, up to
    /// 64 bytes in size.
    uint8_t cgc_seed[S2E_DECREEMON_MAX_SEED_SIZE];

} __attribute__((packed));

#define S2E_DECREEMON_VM_READ (1u << 0)
#define S2E_DECREEMON_VM_WRITE (1u << 1)
#define S2E_DECREEMON_VM_EXEC (1u << 2)

struct S2E_DECREEMON_VMA {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_INIT {
    uint64_t page_offset;
    uint64_t start_kernel;
    uint64_t task_struct_pid_offset;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND_KERNEL_PANIC {
    uint64_t message;
    uint64_t message_size;
} __attribute__((packed));

struct S2E_DECREEMON_COMMAND {
    uint64_t version;
    enum S2E_DECREEMON_COMMANDS Command;
    uint64_t currentPid;
    union {
        struct S2E_LINUXMON_COMMAND_PROCESS_LOAD ProcessLoad;
        struct S2E_LINUXMON_COMMAND_MODULE_LOAD ModuleLoad;
        struct S2E_DECREEMON_COMMAND_READ_DATA Data;
        struct S2E_DECREEMON_COMMAND_WRITE_DATA WriteData;
        struct S2E_DECREEMON_COMMAND_FD_WAIT FDWait;
        struct S2E_DECREEMON_COMMAND_SEG_FAULT SegFault;
        struct S2E_DECREEMON_COMMAND_RANDOM Random;
        struct S2E_DECREEMON_COMMAND_READ_DATA_POST DataPost;
        struct S2E_DECREEMON_COMMAND_GET_CFG_BOOL GetCfgBool;
        struct S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_SIZE SymbolicSize;
        struct S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER SymbolicBuffer;
        struct S2E_DECREEMON_COMMAND_COPY_TO_USER CopyToUser;
        struct S2E_DECREEMON_COMMAND_UPDATE_MEMORY_MAP UpdateMemoryMap;
        struct S2E_DECREEMON_COMMAND_SET_CB_PARAMS CbParams;
        struct S2E_DECREEMON_COMMAND_INIT Init;
        struct S2E_DECREEMON_COMMAND_KERNEL_PANIC Panic;
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
