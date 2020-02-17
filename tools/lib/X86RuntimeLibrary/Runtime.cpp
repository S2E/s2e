///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
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

extern "C" {
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu-common.h>
}

#include <stdio.h>
#include <sys/mman.h>

#include <BitcodeLibrary/Runtime.h>

// #define DEBUG_RUNTIME
// #define DEBUG_MEMORY

#ifdef DEBUG_RUNTIME
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

#ifdef DEBUG_MEMORY
#define mprintf(...) printf(__VA_ARGS__)
#else
#define mprintf(...)
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))

extern "C" {
FILE *logfile = NULL;
int loglevel = 0;
extern CPUArchState *env;
CPUArchState myenv;

char *g_syscall_transmit_data = NULL;
size_t g_syscall_transmit_size = 0;
int g_syscall_transmit_fd = 0;

struct se_libcpu_interface_t g_sqi;

static uint64_t translate_pointer(uint64_t pointer);

static void print_regs() {
    printf("EAX=%x EBX=%x ECX=%x EDX=%x EBP=%x ESP=%x ESI=%x EDI=%x\n", env->regs[R_EAX], env->regs[R_EBX],
           env->regs[R_ECX], env->regs[R_EDX], env->regs[R_EBP], env->regs[R_ESP], env->regs[R_ESI], env->regs[R_EDI]);
}

static void not_usable_statically(const char *function, const char *filename, int line) {
    if (__revgen_detect_library_functions) {
        printf("Called function that is not usable statically %s %s:%d\n", function, filename, line);
        dosegfault();
    }

    assert(false && "Not usable statically");
}

/***********************************************************/
#define DEFINE_MMU_LD(T, sz, suffix)                                                               \
    T helper_ld##sz##_##suffix(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr) { \
        target_ulong tptr = translate_pointer(addr);                                               \
        T ret = *(T *) (tptr);                                                                     \
        mprintf("R[%llx => %llx]=%llx\n", (uint64_t) addr, (uint64_t) tptr, (uint64_t) ret);       \
        return ret;                                                                                \
    }

#define DEFINE_MMU_ST(T, sz, suffix)                                                                          \
    void helper_st##sz##_##suffix(CPUArchState *env, target_ulong addr, T data, int mmu_idx, void *retaddr) { \
        mprintf("W[%llx]=%llx\n", (uint64_t) addr, (uint64_t) data);                                          \
        *(T *) (translate_pointer(addr)) = data;                                                              \
    }

DEFINE_MMU_LD(uint8_t, b, mmu)
DEFINE_MMU_LD(uint16_t, w, mmu)
DEFINE_MMU_LD(uint32_t, l, mmu)
DEFINE_MMU_LD(uint64_t, q, mmu)

DEFINE_MMU_ST(uint8_t, b, mmu)
DEFINE_MMU_ST(uint16_t, w, mmu)
DEFINE_MMU_ST(uint32_t, l, mmu)
DEFINE_MMU_ST(uint64_t, q, mmu)

/***********************************************************/
#define DEFINE_MEM_LD(T, sz, suffix)             \
    T cpu_ld##sz##_##suffix(target_ulong addr) { \
        return *(T *) (translate_pointer(addr)); \
    }

DEFINE_MEM_LD(uint64_t, q, data)
DEFINE_MEM_LD(uint32_t, l, kernel)
DEFINE_MEM_LD(uint32_t, l, data)
DEFINE_MEM_LD(uint16_t, uw, kernel)
DEFINE_MEM_LD(uint16_t, uw, data)
DEFINE_MEM_LD(int16_t, sw, data)
DEFINE_MEM_LD(uint8_t, ub, kernel)
DEFINE_MEM_LD(uint8_t, ub, data)

/***********************************************************/

#define DEFINE_MEM_ST(T, sz, suffix)                        \
    void cpu_st##sz##_##suffix(target_ulong addr, T data) { \
        *(T *) (translate_pointer(addr)) = data;            \
    }

DEFINE_MEM_ST(uint64_t, q, data)
DEFINE_MEM_ST(uint32_t, l, kernel)
DEFINE_MEM_ST(uint32_t, l, data)
DEFINE_MEM_ST(int16_t, w, kernel)
DEFINE_MEM_ST(uint16_t, uw, kernel)
DEFINE_MEM_ST(int16_t, w, data)
DEFINE_MEM_ST(uint8_t, ub, kernel)
DEFINE_MEM_ST(int8_t, b, kernel)
DEFINE_MEM_ST(int8_t, b, data)

/***********************************************************/
#define DEFINE_MEM_PHYS_LD(T, sz, suffix)          \
    T ld##sz##_##suffix(target_phys_addr_t addr) { \
        assert(false);                             \
    }

DEFINE_MEM_PHYS_LD(uint32_t, ub, phys)
DEFINE_MEM_PHYS_LD(uint32_t, uw, phys)
DEFINE_MEM_PHYS_LD(uint32_t, l, phys)
DEFINE_MEM_PHYS_LD(uint64_t, q, phys)

void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void stq_phys_notdirty(target_phys_addr_t addr, uint64_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void stb_phys(target_phys_addr_t addr, uint32_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void stw_phys(target_phys_addr_t addr, uint32_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void stl_phys(target_phys_addr_t addr, uint32_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void stq_phys(target_phys_addr_t addr, uint64_t val) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

/***********************************************************/

void tlb_flush_page(CPUArchState *env, target_ulong addr) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int tlb_set_page_exec(CPUArchState *env, target_ulong vaddr, target_phys_addr_t paddr, int prot, int mmu_idx,
                      int is_softmmu) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void tlb_flush(CPUArchState *env, int flush_global) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void helper_register_symbol(const char *name, void *address) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void run_on_cpu(CPUArchState *env, void (*func)(void *data), void *data) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

bool tcg_enabled(void) {
    return true;
}

void kvm_cpu_synchronize_state(CPUArchState *env) {
    assert(false);
}

void do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw) {
    assert(false);
}

void tlb_set_page(CPUArchState *env, target_ulong vaddr, target_phys_addr_t paddr, int prot, int mmu_idx,
                  target_ulong size) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int cpu_x86_register(cpuid_t *cpuid, const char *cpu_model, int is64) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_x86_cpuid(cpuid_t *cpuid, uint32_t index, uint32_t count, uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                   uint32_t *edx) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

/***********************************************************/

int cpu_breakpoint_insert(CPUX86State *env, target_ulong pc, int flags, CPUBreakpoint **breakpoint) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int cpu_breakpoint_remove(CPUArchState *env, target_ulong pc, int flags) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_breakpoint_remove_all(CPUArchState *env, int mask) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_breakpoint_remove_by_ref(CPUArchState *env, CPUBreakpoint *breakpoint) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int cpu_watchpoint_insert(CPUArchState *env, target_ulong addr, target_ulong len, int flags,
                          CPUWatchpoint **watchpoint) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_watchpoint_remove_all(CPUArchState *env, int mask) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_watchpoint_remove_by_ref(CPUArchState *env, CPUWatchpoint *watchpoint) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void hw_breakpoint_insert(CPUX86State *env, int index) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void hw_breakpoint_remove(CPUX86State *env, int index) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int check_hw_breakpoints(CPUX86State *env, int force_dr6_update) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_io_recompile(CPUArchState *env, void *retaddr) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_loop_exit(CPUArchState *env) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_resume_from_signal(CPUArchState *env1, void *puc) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_abort(CPUArchState *env, const char *fmt, ...) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

int cpu_memory_rw_debug(CPUArchState *env, target_ulong addr, uint8_t *buf, int len, int is_write) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_exec_init(CPUArchState *env) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_x86_update_cr3(CPUX86State *env, uint32_t new_cr3) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void cpu_dump_state(CPUArchState *env, FILE *f, fprintf_function cpu_fprintf, int flags) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

uint64_t cpu_get_tsc(void) {
    uint32_t low, high;
    int64_t val;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}

void cpu_exit(CPUArchState *s) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

void LIBCPU_NORETURN cpu_loop_exit_restore(CPUArchState *env1, uintptr_t ra) {
    not_usable_statically(__FUNCTION__, __FILE__, __LINE__);
}

/**********************************/

extern uint64_t revgen_function_count;
extern revgen_function_t *revgen_function_pointers;
extern uint64_t *revgen_function_addresses;

void call_marker(target_ulong pc) {
    for (unsigned i = 0; i < revgen_function_count; ++i) {
        if (pc == revgen_function_addresses[i]) {
            dprintf("Calling %llx\n", (uint64_t) pc);
            revgen_function_pointers[i](&myenv);
            return;
        }
    }

    printf("Binary tried to call unknown function %x\n", pc);

    if (__revgen_detect_library_functions) {
        dosegfault();
    }

    exit(-1);
}

void incomplete_marker(target_ulong pc) {
    printf("Reached incompletely recovered code %#x\n", pc);

    if (__revgen_detect_library_functions) {
        dosegfault();
    }

    exit(-1);
}

void revgen_trace(target_ulong pc) {
    printf("Tracing %#x\n", pc);
}

/**********************************/

extern unsigned section_count;

extern uint8_t **section_ptrs;
extern uint64_t *section_vas;
extern uint64_t *section_sizes;

static uint64_t translate_pointer(uint64_t pointer) {
    for (unsigned i = 0; i < section_count; ++i) {
        uint8_t *ptr = section_ptrs[i];
        uint64_t start = section_vas[i];
        uint64_t size = section_sizes[i];

        if (pointer >= start && pointer < start + size) {
            uint64_t ret = (uintptr_t) ptr + (pointer - start);
            mprintf("%#llx => %#llx [sec %p]\n", pointer, ret, ptr);
            return ret;
        }
    }

    if (__revgen_detect_library_functions) {
        __revgen_validate_pointer(pointer);
    }

    return pointer;
}

static void handle_cgcos_transmit(target_ulong *args) {
    int fd = args[0];
    void *buffer = (void *) translate_pointer(args[1]);
    unsigned size = args[2];
    size_t count;

    if (__revgen_detect_library_functions) {
        dprintf("%s buffer: %p size: %d", __FUNCTION__, buffer, size);
        if (size > 10000) {
            /* Function detection would never send a size that big */
            dprintf("\n");
            dosegfault();
        }

        g_syscall_transmit_data = (char *) realloc(g_syscall_transmit_data, g_syscall_transmit_size + size);
        memcpy(g_syscall_transmit_data + g_syscall_transmit_size, buffer, size);
        g_syscall_transmit_size += size;
        /* XXX: fd might change from call to call */
        g_syscall_transmit_fd = fd;
        count = size;
        dprintf(" content: %s\n", buffer);
    } else {
        count = write(fd, buffer, size);
    }

    if (args[3]) {
        *(size_t *) args[3] = count;
    }

    myenv.regs[R_EAX] = 0;

    if (count < 0) {
        if (args[3]) {
            *(size_t *) args[3] = 0;
        }
        myenv.regs[R_EAX] = count;
    }
}

static void handle_cgcos_receive(target_ulong *args) {
    int fd = args[0];
    void *buffer = (void *) translate_pointer(args[1]);
    unsigned size = args[2];
    size_t count = read(fd, buffer, size);

    if (args[3]) {
        *(size_t *) args[3] = count;
    }

    myenv.regs[R_EAX] = 0;

    if (count < 0) {
        if (args[3]) {
            *(size_t *) args[3] = 0;
        }
        myenv.regs[R_EAX] = count;
    }
}

static void handle_cgcos_fdwait(target_ulong *args) {
    // cgcos_fdwait(int nfds, fd_set __user *readfds, fd_set __user *writefds,
    // struct timeval __user *timeout, int __user *readyfds)
    int nfds = args[0];
    fd_set *readfds = (fd_set *) translate_pointer(args[1]);
    fd_set *writefds = (fd_set *) translate_pointer(args[2]);
    struct timeval *timeout = (struct timeval *) args[3];
    int *readyfds = (int *) args[4];
    int res = select(nfds, readfds, writefds, NULL, timeout);
    dprintf("select returned %d (%d %s)\n", res, errno, strerror(errno));
    myenv.regs[R_EAX] = 0;
    if (res < 0) {
        myenv.regs[R_EAX] = errno;
    } else {
        if (readyfds) {
            *readyfds = res;
        }
    }
}

static void handle_cgcos_allocate(target_ulong *args) {
    unsigned long len = args[0];
    unsigned long exec = args[1];
    void **addr = (void **) translate_pointer(args[2]);

    int prot = PROT_READ | PROT_WRITE;
    if (exec) {
        prot |= PROT_EXEC;
    }

    void *ret = mmap(NULL, len, prot, MAP_ANON | MAP_PRIVATE, -1, 0);
    *addr = NULL;
    if (ret == MAP_FAILED) {
        *addr = NULL;
        myenv.regs[R_EAX] = errno;
        dprintf("Alloc failed len=%x errno=%d (%s)\n", len, errno, strerror(errno));
    } else {
        *addr = ret;
        myenv.regs[R_EAX] = 0;
        dprintf("Allocated %p len=%#x\n", ret, len);
    }
}

static void handle_cgcos_unmap(target_ulong *args) {
    dprintf("mmap %p len=%#x\n", (void *) args[0], args[1]);
    int ret = munmap((void *) args[0], args[1]);
    myenv.regs[R_EAX] = 0;
    if (ret < 0) {
        myenv.regs[R_EAX] = errno;
        dprintf("munmap failed len=%x errno=%d (%s)\n", args[1], errno, strerror(errno));
    }
}

static void handle_cgcos_random(target_ulong *args) {
    char *buf = (char *) translate_pointer(args[0]);
    size_t count = args[1];
    size_t *out = (size_t *) translate_pointer(args[2]);
    for (size_t i = 0; i < count; ++i) {
        uint32_t randval = rand();
        size_t size = min(count - i, sizeof(randval));
        if (buf) {
            memcpy(&buf[i], &randval, size);
        }
    }

    if (out) {
        memcpy(out, &count, sizeof(*out));
    }
}

void helper_raise_interrupt(int intno, int next_eip_addend) {
    target_ulong syscall_number = myenv.regs[R_EAX];
    target_ulong args[6];
    args[0] = myenv.regs[R_EBX];
    args[1] = myenv.regs[R_ECX];
    args[2] = myenv.regs[R_EDX];
    args[3] = myenv.regs[R_ESI];
    args[4] = myenv.regs[R_EDI];
    args[5] = myenv.regs[R_EBP];

    dprintf("syscall %d - args: %08x %08x %08x %08x %08x %08x\n", syscall_number, args[0], args[1], args[2], args[3],
            args[4], args[5]);

    if (__revgen_detect_library_functions && syscall_number != 2) { // TODO: support other calls
        dosegfault();
    }

    switch (syscall_number) {
        case 1: {
            exit(args[0]);
        } break;

        case 2: {
            handle_cgcos_transmit(args);
        } break;

        case 3: {
            handle_cgcos_receive(args);
        } break;

        case 4: {
            handle_cgcos_fdwait(args);
        } break;

        case 5: {
            handle_cgcos_allocate(args);
        } break;

        case 6: {
            handle_cgcos_unmap(args);
        } break;

        case 7: {
            handle_cgcos_random(args);
        } break;

        default: {
            printf("Unsupported syscall %d\n", syscall_number);
            exit(-1);
        } break;
    }
}

/**********************************/

void g_free(void *p) {
    assert(false && "TODO: fix libs");
}

static int default_main(int argc, char **argv) {
    const unsigned STACK_SIZE = 0x100000;
    char *stack = (char *) malloc(STACK_SIZE);

    // Initialize the eflags register to what a normal Linux
    // process would get when executing its first instruction.
    // Bit 1 is reserved and always set.
    uint32_t eflags = IF_MASK | 0x2;

    myenv.cc_op = CC_OP_EFLAGS;
    myenv.cc_src = eflags & CFLAGS_MASK;
    myenv.df = (eflags & DF_MASK) ? -1 : 1;
    myenv.mflags = eflags & MFLAGS_MASK;

    myenv.regs[R_ESP] = (target_ulong)(stack + STACK_SIZE - 0x10);

    revgen_entrypoint(&myenv);

    free(stack);

    return env->regs[R_EAX];
}

int main(int argc, char **argv) {
    env = &myenv;

    if (!__detect_library_functions(argc, argv)) {
        return 0;
    }

    return default_main(argc, argv);
}
}
