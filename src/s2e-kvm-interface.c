///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cpu/kvm.h>

#include <cpu/cpus.h>
#include <cpu/exec.h>
#include <cpu/memory.h>
#include <libcpu-log.h>
#include <timer.h>

#include "coroutine.h"

#ifdef CONFIG_SYMBEX
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_libcpu.h>
#endif

#include <cpu/cpu-common.h>
#include <cpu/i386/cpu.h>
#include <cpu/ioport.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

#include "s2e-kvm-interface.h"

// We may need a very large stack in case of deep expressions.
// Default stack is a few megabytes, it's not enough.
static const uint64_t S2E_STACK_SIZE = 1024 * 1024 * 1024;

// XXX: make this clean
int s2e_dev_save(const void *buffer, size_t size);
int s2e_dev_restore(void *buffer, int pos, size_t size);

extern CPUX86State *env;
extern void *g_s2e;

// Convenience variable to help debugging in gdb.
// env is present in both inside qemu and libs2e, which
// causes confusion.
CPUX86State *g_cpu_env;

#define false 0

int g_signal_pending = 0;

struct stats_t g_stats;

static const int MAX_MEMORY_SLOTS = 32;

// Indicates that the cpu loop returned with a coroutine switch.
// This happens when an instruction had to suspend its execution
// to let the kvm client handle the operation (e.g., mmio, snapshot, etc.).
int g_handling_kvm_cb;

static const int CPU_EXIT_SIGNAL = SIGUSR2;
bool g_cpu_thread_id_inited = false;
pthread_t g_cpu_thread_id;

static volatile bool s_in_kvm_run = false;
static volatile bool s_s2e_exiting = false;
static volatile bool s_timer_exited = false;

static pthread_mutex_t s_cpu_lock;
static pthread_t s_timer_thread;

extern struct cpu_io_funcs_t g_io;

static void s2e_kvm_cpu_exit_signal(int signum) {
    env->kvm_request_interrupt_window = 1;
    cpu_exit(env);
}

///
/// \brief s2e_kvm_send_cpu_exit_signal sends a signal
/// to the cpu loop thread in order to exit the cpu loop.
///
/// It is important to use a signal that executes on the
/// same thread as the cpu loop in order to avoid race conditions
/// and complex locking.
///
static void s2e_kvm_send_cpu_exit_signal(void) {
    if (!g_cpu_thread_id_inited) {
        return;
    }

    if (pthread_kill(g_cpu_thread_id, CPU_EXIT_SIGNAL) < 0) {
        abort();
    }
}

static void *timer_cb(void *param) {
    while (!s_s2e_exiting) {
        usleep(100 * 1000);

        // Required for shutdown, otherwise kvm clients may get stuck
        // Also required to give a chance timers to run
        s2e_kvm_send_cpu_exit_signal();
    }

    s_timer_exited = true;
    return NULL;
}

#ifdef CONFIG_SYMBEX
#include <s2e/s2e_config.h>
#include <tcg/tcg-llvm.h>

const char *g_s2e_config_file = NULL;
const char *g_s2e_output_dir;
const char *g_s2e_shared_dir = NULL;
int g_execute_always_klee = 0;
int g_s2e_verbose = 0;
int g_s2e_max_processes = 1;

static void s2e_terminate_timer_thread() {
    s_s2e_exiting = true;
    while (!s_timer_exited)
        ;
}

static void s2e_cleanup(void) {
    s2e_terminate_timer_thread();

    if (g_s2e) {
        monitor_close();
        s2e_close();
        g_s2e = NULL;
    }
}

static void s2e_init(void) {
    tcg_llvm_ctx = tcg_llvm_initialize();

    g_s2e_config_file = getenv("S2E_CONFIG");

    if (!g_s2e_config_file) {
        fprintf(stderr, "Warning: S2E_CONFIG environment variable was not specified, "
                        "using the default (empty) config file\n");
    }

    g_s2e_output_dir = getenv("S2E_OUTPUT_DIR");

    int argc = 0;
    char **argv = {NULL};

    if (monitor_init() < 0) {
        exit(-1);
    }

    int unbuffered_stream = 0;
    const char *us = getenv("S2E_UNBUFFERED_STREAM");
    if (us && us[0] == '1') {
        unbuffered_stream = 1;
    }

    const char *max_processes = getenv("S2E_MAX_PROCESSES");
    if (max_processes) {
        g_s2e_max_processes = strtol(max_processes, NULL, 0);
    }

    s2e_initialize(argc, argv, tcg_llvm_ctx, g_s2e_config_file, g_s2e_output_dir, unbuffered_stream, g_s2e_verbose,
                   g_s2e_max_processes);

    s2e_create_initial_state();

    atexit(s2e_cleanup);
}

#endif

/**** /dev/kvm ioctl handlers *******/

int s2e_kvm_get_api_version(void) {
    return KVM_API_VERSION;
}

int s2e_kvm_check_extension(int kvm_fd, int capability) {
    switch (capability) {
        case KVM_CAP_NR_MEMSLOTS: {
            return MAX_MEMORY_SLOTS;
        } break;

        case KVM_CAP_MP_STATE:
        case KVM_CAP_EXT_CPUID:
        case KVM_CAP_SET_TSS_ADDR:
        case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
        case KVM_CAP_USER_MEMORY:
        case KVM_CAP_NR_VCPUS:
        case KVM_CAP_MAX_VCPUS:

        /* libs2e-specific calls */
        case KVM_CAP_MEM_RW:
        case KVM_CAP_FORCE_EXIT:
            return 1;

#ifdef CONFIG_SYMBEX
        case KVM_CAP_DISK_RW:
        case KVM_CAP_CPU_CLOCK_SCALE:
            return 1;
#endif

// Per-path disk state support is only available with symbex builds.
// Can't write snapshot files there.
#ifdef CONFIG_SYMBEX_MP
        case KVM_CAP_DEV_SNAPSHOT:
            return 1;
#endif

        default:
// return s_original_ioctl(fd, request, arg1);
#ifdef SE_KVM_DEBUG_INTERFACE
            printf("Unsupported cap %x\n", capability);
#endif
            return -1;
    }
}

///
/// \brief s2e_kvm_init_log_level initializes the libcpu log level.
///
/// This is the same as the -d switch from vanilla QEMU.
///
static void s2e_kvm_init_log_level() {
    loglevel = 0;
    const char *libcpu_log_level = getenv("LIBCPU_LOG_LEVEL");
    if (libcpu_log_level) {
        loglevel = cpu_str_to_log_mask(libcpu_log_level);
    }

    const char *libcpu_log_file = getenv("LIBCPU_LOG_FILE");
    if (libcpu_log_file) {
        logfile = fopen(libcpu_log_file, "w");
        if (!logfile) {
            printf("Could not open log file %s\n", libcpu_log_file);
            exit(-1);
        }
    } else {
        logfile = stdout;
    }
}

static int s2e_kvm_init_timer_thread(void) {
    int ret;
    pthread_attr_t attr;

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        fprintf(stderr, "Could not init thread attributes\n");
        goto err1;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        fprintf(stderr, "Could not set detached state for thread\n");
        goto err1;
    }

    ret = pthread_create(&s_timer_thread, &attr, timer_cb, NULL);
    if (ret < 0) {
        fprintf(stderr, "could not create timer thread\n");
        goto err1;
    }

    pthread_attr_destroy(&attr);

err1:
    return ret;
}

static int s2e_kvm_init_cpu_lock(void) {
    int ret = pthread_mutex_init(&s_cpu_lock, NULL);
    if (ret < 0) {
        fprintf(stderr, "Could not init cpu lock\n");
    }

    return ret;
}

int s2e_kvm_create_vm(int kvm_fd) {
    /* Reserve a dummy file descriptor */
    int fd = open("/dev/null", O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        goto err1;
    }

#ifdef CONFIG_SYMBEX
    init_s2e_libcpu_interface(&g_sqi);
#endif

    cpu_register_io(&g_io);
    tcg_exec_init(0);
    s2e_kvm_init_log_level();

    x86_cpudef_setup();

/* We want the default libcpu CPU, not the KVM one. */
#if defined(TARGET_X86_64)
    g_cpu_env = env = cpu_x86_init("qemu64-s2e");
#elif defined(TARGET_I386)
    g_cpu_env = env = cpu_x86_init("qemu32-s2e");
#else
#error unknown architecture
#endif
    if (!env) {
        printf("Could not create cpu\n");
        goto err2;
    }

    g_cpu_env->v_apic_base = 0xfee00000;
    g_cpu_env->size = sizeof(*g_cpu_env);

    if (s2e_kvm_init_cpu_lock() < 0) {
        exit(-1);
    }

    init_clocks();

    if (s2e_kvm_init_timer_thread() < 0) {
        exit(-1);
    }

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = s2e_kvm_cpu_exit_signal;

    if (sigaction(CPU_EXIT_SIGNAL, &act, NULL) < 0) {
        perror("Could not initialize cpu exit signal");
        exit(-1);
    }

#ifdef CONFIG_SYMBEX
    g_s2e_shared_dir = getenv("S2E_SHARED_DIR");
    if (!g_s2e_shared_dir) {
        fprintf(stderr, "Warning: S2E_SHARED_DIR environment variable was not specified, "
                        "using %s\n",
                CONFIG_LIBCPU_DATADIR);
        g_s2e_shared_dir = CONFIG_LIBCPU_DATADIR;
    }

    s2e_init();

    // Call it twice, because event pointers are only known
    // after s2e is inited.
    init_s2e_libcpu_interface(&g_sqi);

    s2e_register_cpu(env);

    s2e_init_device_state();
    s2e_init_timers();

    s2e_initialize_execution(g_execute_always_klee);
    s2e_register_dirty_mask((uint64_t) get_ram_list_phys_dirty(), get_ram_list_phys_dirty_size() >> TARGET_PAGE_BITS);
    s2e_on_initialization_complete();
#endif

    do_cpu_init(env);

    return fd;

err2:
    close(fd);
err1:
    return fd;
}

int s2e_kvm_get_vcpu_mmap_size(void) {
    return 0x10000; /* Some magic value */
}

/**** vm ioctl handlers *******/

struct kvm_run *g_kvm_vcpu_buffer;
static Coroutine *s_kvm_cpu_coroutine;

int s2e_kvm_vm_create_vcpu(int vm_fd) {
    size_t size = s2e_kvm_get_vcpu_mmap_size();
    g_kvm_vcpu_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    // Magic file descriptor
    // We don't need a real one, just something to recognize ioctl calls.
    g_kvm_vcpu_fd = vm_fd + 234234;
    cpu_exec_init_all();
    return g_kvm_vcpu_fd;
}

int s2e_kvm_vm_set_user_memory_region(int vm_fd, struct kvm_userspace_memory_region *region) {
    // This must never be called while another thread is in the cpu loop
    // because it will cause race conditions with the TLB and the ram structures.
    s2e_kvm_request_exit();
    pthread_mutex_lock(&s_cpu_lock);

    assert(!s_in_kvm_run);
    tlb_flush(env, 1);
    mem_desc_unregister(region->slot);
    mem_desc_register(region);

    pthread_mutex_unlock(&s_cpu_lock);

    return 0;
}

int s2e_kvm_vm_register_fixed_region(int vm_fd, struct kvm_fixed_region *region) {
#ifdef CONFIG_SYMBEX_MP
    s2e_register_ram2(region->name, region->host_address, region->size, region->flags & KVM_MEM_SHARED_CONCRETE);
#endif
    return 0;
}

int s2e_kvm_vm_disk_rw(int vm_fd, struct kvm_disk_rw *d) {
#ifdef CONFIG_SYMBEX
    if (d->is_write) {
        d->count = s2e_bdrv_write(NULL, d->sector, (uint8_t *) d->host_address, d->count);
    } else {
        d->count = s2e_bdrv_read(NULL, d->sector, (uint8_t *) d->host_address, d->count);
    }
    return 0;
#else
    return -1;
#endif
}

int s2e_kvm_vm_dev_snapshot(int vm_fd, struct kvm_dev_snapshot *s) {
#ifdef CONFIG_SYMBEX_MP
    if (s->is_write) {
        return s2e_dev_save((void *) s->buffer, s->size);
    } else {
        return s2e_dev_restore((void *) s->buffer, s->pos, s->size);
    }
#else
    return -1;
#endif
}

int s2e_kvm_vm_enable_cap(int vm_fd, struct kvm_enable_cap *cap) {
    printf("enabling not supported capability %d\n", cap->cap);
    errno = 1;
    return -1;
}

int s2e_kvm_vm_ioeventfd(int vm_fd, struct kvm_ioeventfd *event) {
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("kvm_ioeventd datamatch=%#llx addr=%#llx len=%d fd=%d flags=%#" PRIx32 "\n", event->datamatch, event->addr,
           event->len, event->fd, event->flags);
#endif
    return -1;
}

int s2e_kvm_vm_set_identity_map_addr(int vm_fd, uint64_t addr) {
    assert(false && "Not implemented");
}

///
/// \brief s2e_kvm_vm_get_dirty_log returns a bitmap of dirty pages
/// for the given memory buffer.
///
/// This is usually used for graphics memory by kvm clients.
///
/// \param vm_fd the virtual machine fd
/// \param log the bitmap structure
/// \return
///
int s2e_kvm_vm_get_dirty_log(int vm_fd, struct kvm_dirty_log *log) {
    s2e_kvm_request_exit();

    const MemoryDesc *r = mem_desc_get_slot(log->slot);

    if (s_s2e_exiting) {
        // This may happen if we are called from an exit handler, e.g., if
        // plugin code called exit() from the cpu loop. We don't want
        // to deadlock in this case, so return conservatively all dirty.
        memset(log->dirty_bitmap, 0xff, (r->kvm.memory_size >> TARGET_PAGE_BITS) / 8);
        return 0;
    }

    pthread_mutex_trylock(&s_cpu_lock);

    cpu_physical_memory_get_dirty_bitmap(log->dirty_bitmap, r->ram_addr, r->kvm.memory_size, VGA_DIRTY_FLAG);

    cpu_physical_memory_reset_dirty(r->ram_addr, r->ram_addr + r->kvm.memory_size - 1, VGA_DIRTY_FLAG);

    pthread_mutex_unlock(&s_cpu_lock);
    return 0;
}

///
/// \brief s2e_kvm_vm_mem_rw intercepts all dma read/writes from the kvm client.
///
/// This is important in order to keep the cpu code cache consistent as well
/// as to keep track of dirty page.
///
/// In multi-path mode, this ensures that dma reads/writes go to the right state
/// in addition to keeping track of dirty pages.
///
/// \param vm_fd the vm descriptor
/// \param mem the memory descriptor
/// \return
///
int s2e_kvm_vm_mem_rw(int vm_fd, struct kvm_mem_rw *mem) {
#if !defined(CONFIG_SYMBEX_MP)
    if (!mem->is_write) {
        // Fast path for reads
        // TODO: also do it for writes
        memcpy((void *) mem->dest, (void *) mem->source, mem->length);
        return 0;
    }
#endif

    s2e_kvm_request_exit();
    pthread_mutex_lock(&s_cpu_lock);
    cpu_host_memory_rw(mem->source, mem->dest, mem->length, mem->is_write);
    pthread_mutex_unlock(&s_cpu_lock);
    return 0;
}

int s2e_kvm_set_clock_scale_ptr(int vm_fd, unsigned *scale) {
#ifdef CONFIG_SYMBEX
    if (!scale) {
        return -1;
    }

    g_sqi.exec.clock_scaling_factor = scale;
    return 0;
#else
    return -1;
#endif
}

/**** vcpu ioctl handlers *******/

int s2e_kvm_vcpu_get_clock(int vcpu_fd, struct kvm_clock_data *clock) {
    assert(false && "Not implemented");
}

static unsigned s_s2e_kvm_sigmask_size;

static union {
    sigset_t sigset;
    uint8_t bytes[32];
} s_s2e_kvm_sigmask;

// Defines which signals are blocked during execution of kvm.
int s2e_kvm_vcpu_set_signal_mask(int vcpu_fd, struct kvm_signal_mask *mask) {
    // XXX: doesn't seem to matter for typical kvm clients,
    // not sure what the implications of spurious signals are.
    s_s2e_kvm_sigmask_size = mask->len;
    for (unsigned i = 0; i < mask->len; ++i) {
#ifdef SE_KVM_DEBUG_INTERFACE
        printf("  signals %#04x\n", mask->sigset[i]);
#endif
        s_s2e_kvm_sigmask.bytes[i] = mask->sigset[i];
    }
    return 0;
}

static void block_signals(void) {
    sigdelset(&s_s2e_kvm_sigmask.sigset, CPU_EXIT_SIGNAL);
    if (pthread_sigmask(SIG_BLOCK, &s_s2e_kvm_sigmask.sigset, NULL) < 0) {
        abort();
    }
}

static void unblock_signals(void) {
    sigaddset(&s_s2e_kvm_sigmask.sigset, CPU_EXIT_SIGNAL);
    if (pthread_sigmask(SIG_UNBLOCK, &s_s2e_kvm_sigmask.sigset, NULL) < 0) {
        abort();
    }
}

void s2e_kvm_flush_disk(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_FLUSH_DISK;
    coroutine_yield();
}

void s2e_kvm_save_device_state(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_SAVE_DEV_STATE;
    coroutine_yield();
}

void s2e_kvm_restore_device_state(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_RESTORE_DEV_STATE;
    coroutine_yield();
}

void s2e_kvm_clone_process(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_CLONE_PROCESS;

    coroutine_yield();

    if (s2e_kvm_init_timer_thread() < 0) {
        exit(-1);
    }

    g_cpu_thread_id = pthread_self();
}

static void coroutine_fn s2e_kvm_cpu_coroutine(void *opaque) {
#ifdef SE_KVM_DEBUG_IRQ
    static uint64_t prev_mflags = 0;
#endif

    while (1) {
        libcpu_run_all_timers();

        assert(env->current_tb == NULL);

        // XXX: need to save irq state on state switches
        if (env->kvm_irq != -1) {
            if (env->interrupt_request == 0) {
                printf("Forcing IRQ\n");
            }
            env->interrupt_request |= CPU_INTERRUPT_HARD;
        }

#ifdef SE_KVM_DEBUG_IRQ
        if (env->interrupt_request & CPU_INTERRUPT_HARD) {
            printf("Handling IRQ %d req=%#x hflags=%x hflags2=%#x mflags=%#lx tpr=%#x esp=%#lx signal=%d\n",
                   env->kvm_irq, env->interrupt_request, env->hflags, env->hflags2, (uint64_t) env->mflags, env->v_tpr,
                   (uint64_t) env->regs[R_ESP], g_signal_pending);
        }
#endif

        env->kvm_request_interrupt_window |= g_kvm_vcpu_buffer->request_interrupt_window;

#ifdef SE_KVM_DEBUG_IRQ
        prev_mflags = env->mflags;
        uint64_t prev_eip = env->eip;
#endif

        env->exit_request = 0;
        cpu_x86_exec(env);
// printf("cpu_exec return %#x\n", ret);

#ifdef SE_KVM_DEBUG_IRQ
        bool mflags_changed = (prev_mflags != env->mflags);
        if (mflags_changed) {
            printf("mflags changed: %lx old=%lx new=%lx reqwnd=%d peip=%lx, eip=%lx\n", (uint64_t) mflags_changed,
                   (uint64_t) prev_mflags, (uint64_t) env->mflags, g_kvm_vcpu_buffer->request_interrupt_window,
                   (uint64_t) prev_eip, (uint64_t) env->eip);
        }
        prev_mflags = env->mflags;
#endif

        assert(env->current_tb == NULL);

        env->exception_index = 0;
        coroutine_yield();
    }
}

int s2e_kvm_vcpu_run(int vcpu_fd) {
    int ret = 0;

    ++g_stats.kvm_runs;

    if (!s_kvm_cpu_coroutine) {
        s_kvm_cpu_coroutine = coroutine_create(s2e_kvm_cpu_coroutine, S2E_STACK_SIZE);
        if (!s_kvm_cpu_coroutine) {
            fprintf(stderr, "Could not create cpu coroutine\n");
            exit(-1);
        }
    }

    if (!g_cpu_thread_id_inited) {
        g_cpu_thread_id = pthread_self();
        g_cpu_thread_id_inited = true;
    }

    if (s_s2e_exiting) {
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    /* Return asap if interrupts can be injected */
    g_kvm_vcpu_buffer->if_flag = (env->mflags & IF_MASK) != 0;
    g_kvm_vcpu_buffer->apic_base = env->v_apic_base;
    g_kvm_vcpu_buffer->cr8 = env->v_tpr;

    g_kvm_vcpu_buffer->ready_for_interrupt_injection = !g_handling_kvm_cb &&
                                                       g_kvm_vcpu_buffer->request_interrupt_window &&
                                                       g_kvm_vcpu_buffer->if_flag && (env->kvm_irq == -1);

    if (g_kvm_vcpu_buffer->ready_for_interrupt_injection) {
#ifdef SE_KVM_DEBUG_IRQ
        printf("%s early ret for ints\n", __FUNCTION__);
#endif
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        return 0;
    }

    block_signals();
    pthread_mutex_lock(&s_cpu_lock);

    s_in_kvm_run = true;

#ifdef SE_KVM_DEBUG_RUN
    if (!g_handling_kvm_cb) {
        printf("%s riw=%d cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
               (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    g_kvm_vcpu_buffer->exit_reason = -1;

    /**
     * Some KVM clients do not set this when calling kvm_run, although the KVM
     * spec says they should. For now, we patch the clients to pass the right value.
     * Eventually, we'll need to figure out how KVM handles it.
     * Having an incorrect (null) APIC base will cause the APIC to get stuck.
     */
    env->v_apic_base = g_kvm_vcpu_buffer->apic_base;
    env->v_tpr = g_kvm_vcpu_buffer->cr8;

    g_handling_kvm_cb = 0;

    coroutine_enter(s_kvm_cpu_coroutine, NULL);

    if (s_s2e_exiting) {
        pthread_mutex_unlock(&s_cpu_lock);
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    g_handling_kvm_cb = g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_IO ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_MMIO ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_FLUSH_DISK ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_SAVE_DEV_STATE ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_RESTORE_DEV_STATE ||
                        g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_CLONE_PROCESS;

    // Might not be NULL if resuming from an interrupted I/O
    // assert(env->current_tb == NULL);

    g_kvm_vcpu_buffer->if_flag = (env->mflags & IF_MASK) != 0;
    g_kvm_vcpu_buffer->apic_base = env->v_apic_base;
    g_kvm_vcpu_buffer->cr8 = env->v_tpr;

    // KVM specs says that we should also check for request for interrupt window,
    // but that causes missed interrupts.
    g_kvm_vcpu_buffer->ready_for_interrupt_injection = !g_handling_kvm_cb &&
                                                       g_kvm_vcpu_buffer->request_interrupt_window &&
                                                       g_kvm_vcpu_buffer->if_flag && (env->kvm_irq == -1);

    if (g_kvm_vcpu_buffer->exit_reason == -1) {
        if (env->halted) {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_HLT;
        } else if (g_kvm_vcpu_buffer->ready_for_interrupt_injection) {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        } else {
            g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
            g_signal_pending = 0;
        }
    }

#if defined(SE_KVM_DEBUG_HLT)
    if (g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_HLT) {
        trace_s2e_kvm_run(g_kvm_vcpu_buffer, ret);
    }
#endif

    assert(g_kvm_vcpu_buffer->exit_reason != 1);

#ifdef SE_KVM_DEBUG_RUN
    if (!g_handling_kvm_cb) {
        printf("%s riw=%d rii=%d er=%#x cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
               g_kvm_vcpu_buffer->ready_for_interrupt_injection, g_kvm_vcpu_buffer->exit_reason,
               (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    if (g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_INTR) {
        // This must be set at the very end, because syscalls might
        // overwrite errno.
        errno = EINTR;
        ret = -1;
    }

    assert(ret >= 0 || errno == EINTR);
    assert(g_kvm_vcpu_buffer->exit_reason != -1);

    s_in_kvm_run = false;

    pthread_mutex_unlock(&s_cpu_lock);
    unblock_signals();

    return ret;
}

int s2e_kvm_vcpu_interrupt(int vcpu_fd, struct kvm_interrupt *interrupt) {
#ifdef SE_KVM_DEBUG_IRQ
    printf("IRQ %d env->mflags=%lx hflags=%x hflags2=%x ptr=%#x\n", interrupt->irq, (uint64_t) env->mflags, env->hflags,
           env->hflags2, env->v_tpr);
    fflush(stdout);
#endif

    if (env->cr[0] & CR0_PE_MASK) {
        assert(interrupt->irq > (env->v_tpr << 4));
    }
    assert(!g_handling_kvm_cb);
    assert(!s_in_kvm_run);
    assert(env->mflags & IF_MASK);
    assert(!(env->interrupt_request & CPU_INTERRUPT_HARD));
    env->interrupt_request |= CPU_INTERRUPT_HARD;
    env->kvm_irq = interrupt->irq;

    return 0;
}

int s2e_kvm_vcpu_nmi(int vcpu_fd) {
    env->interrupt_request |= CPU_INTERRUPT_NMI;
    return 0;
}

///
/// \brief s2e_kvm_request_exit triggers an exit from the cpu loop
///
/// In vanilla KVM, the CPU stops executing guest code when there is
/// an external event pending. Execution can stop at any instruction.
///
/// In our emulated KVM, stopping at any instruction is not possible
/// because of TB chaining, threading, etc.
///
/// This may cause missed interrupts. The KVM client is ready to inject an interrupt,
/// but cannot do so because kvm_run has not exited yet. While it is running,
/// several interrupts of different priorities may be queued up. When kvm_run
/// eventually returns, the highest priority interrupt is injected first.
/// Because DBT is much slower than native execution, it often happens
/// that lower priority don't get to run at all, and higher
/// priority ones are missed.
///
/// Since we can't easily replicate KVM's behavior, we resort to doing
/// what vanilla QEMU in DBT mode would do: interrupt the CPU loop when an interrupt
/// is raised so that the interrupt is scheduled asap.
///
/// This requires adding an extra API to KVM. Things that have been tried
/// to avoid adding the extra API, but did not work properly:
/// - Intercept pthread_kill. KVM client may kick the CPU when an interrupt is ready.
/// This is still too slow.
/// - Intercept eventfd. KVM clients call poll eventfds instead of using signals.
/// Polling for them from a separate thread didn't work either.
///
void s2e_kvm_request_exit(void) {
    if (!env) {
        return;
    }

#ifdef SE_KVM_DEBUG_RUN
    printf("s2e_kvm_request_exit\n");
#endif

    s2e_kvm_send_cpu_exit_signal();
}

///
/// \brief s2e_kvm_request_process_exit cleanly exits
/// the process by sending it SIGTERM
///
/// It is not possible to call exit() directly, as this will
/// abort the process in an unclean manner, possibly causing
/// crashes in other threads.
///
/// Instead, we intercept the exit() call from the S2E plugin
/// and transform it into a signal that the process will use
/// to exit cleanly.
///
/// WARNING: this call aborts the cpu loop without cleaning the
/// stack. Any allocated objects there will leak.
///
/// \param original_exit the original exit() syscall function
/// \param code the exit code
///
void s2e_kvm_request_process_exit(exit_t original_exit, int code) {
    s_s2e_exiting = true;

    if (!s_kvm_cpu_coroutine) {
        original_exit(code);
    }

    coroutine_yield();
    abort();
}
