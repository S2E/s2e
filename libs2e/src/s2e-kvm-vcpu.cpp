///
/// Copyright (C) 2019, Cyberhaven
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

#include <inttypes.h>
#include <memory.h>

#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <timer.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#include <s2e/cpu.h>
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_config.h>
#include <s2e/s2e_libcpu.h>
#include <tcg/tcg-llvm.h>
#include <tcg/utils/bitops.h>
#endif

#if 0
#define SE_KVM_DEBUG_IRQ

#define DPRINTF(...) fprintf(logfile, __VA_ARGS__)
#else
#define DPRINTF(...)
#endif

extern "C" {
void tcg_register_thread(void);
}

#include "s2e-kvm-vcpu.h"
#include "syscalls.h"

extern "C" {
// Convenience variable to help debugging in gdb.
// env is present in both inside qemu and libs2e, which
// causes confusion.
CPUX86State *g_cpu_env;
}

// TODO: remove this global var from libcpu
extern CPUX86State *env;

namespace s2e {
namespace kvm {

kvm_run *g_kvm_vcpu_buffer;
static VCPU *s_vcpu;

// We may need a very large stack in case of deep expressions.
// Default stack is a few megabytes, it's not enough.
static const uint64_t S2E_STACK_SIZE = 1024 * 1024 * 1024;

static const int CPU_EXIT_SIGNAL = SIGUSR2;

VCPU::VCPU(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm, kvm_run *buffer) {
    s_vcpu = this;
    m_kvm = kvm;
    m_vm = vm;
    m_cpuBuffer = buffer;
    assert(!g_kvm_vcpu_buffer);
    g_kvm_vcpu_buffer = buffer;

    tcg_register_thread();

    m_onExit = g_syscalls.onExit.connect(sigc::mem_fun(*this, &VCPU::requestProcessExit));
    m_onSelect = g_syscalls.onSelect.connect(sigc::mem_fun(*this, &VCPU::requestExit));

    if (initCpuLock() < 0) {
        exit(-1);
    }

    /* We want the default libcpu CPU, not the KVM one. */
    m_env = g_cpu_env = env = cpu_x86_init(&m_kvm->getCpuid());

    if (!m_env) {
        DPRINTF("Could not create cpu\n");
        exit(-1);
    }

    m_env->v_apic_base = 0xfee00000;
    m_env->size = sizeof(*m_env);

#ifdef CONFIG_SYMBEX
    s2e_register_cpu(m_env);
#endif

    do_cpu_init(m_env);

    cpu_exec_init_all();
}

VCPU::~VCPU() {
    m_onExit.disconnect();
    m_onSelect.disconnect();
}

std::shared_ptr<VCPU> VCPU::create(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm) {
    size_t size = S2EKVM::getVCPUMemoryMapSize();
    auto buffer = (kvm_run *) ::mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!buffer) {
        return nullptr;
    }

    return std::shared_ptr<VCPU>(new VCPU(kvm, vm, buffer));
}

int VCPU::initCpuLock(void) {
    int ret = pthread_mutex_init(&m_cpuLock, nullptr);
    if (ret < 0) {
        fprintf(stderr, "Could not init cpu lock\n");
    }

    return ret;
}

void VCPU::lock() {
    pthread_mutex_lock(&m_cpuLock);
}

void VCPU::tryLock() {
    pthread_mutex_trylock(&m_cpuLock);
}

void VCPU::unlock() {
    pthread_mutex_unlock(&m_cpuLock);
}

#ifdef SE_KVM_DEBUG_CPUID
static void print_cpuid2(struct kvm_cpuid_entry2 *e) {
    DPRINTF("cpuid function=%#010" PRIx32 " index=%#010" PRIx32 " flags=%#010" PRIx32 " eax=%#010" PRIx32
            " ebx=%#010" PRIx32 " ecx=%#010" PRIx32 " edx=%#010" PRIx32 "\n",
            e->function, e->index, e->flags, e->eax, e->ebx, e->ecx, e->edx);
}
#endif

int VCPU::getClock(kvm_clock_data *clock) {
    assert(false && "Not implemented");
}

int VCPU::setCPUID2(kvm_cpuid2 *cpuid) {
/**
 * QEMU insists on using host cpuid flags when running in KVM mode.
 * We want to use those set in DBT mode instead.
 * TODO: for now, we have no way to configure custom flags.
 * Snapshots will not work if using anything other that defaults.
 */

/// This check ensures that users don't mistakenly use the wrong build of libs2e.
#if defined(TARGET_X86_64)
    if (cpuid->nent == 15) {
        fprintf(stderr, "libs2e for 64-bit guests is used but the KVM client requested 32-bit features\n");
        exit(1);
    }
#elif defined(TARGET_I386)
    if (cpuid->nent == 21) {
        fprintf(stderr, "libs2e for 32-bit guests is used but the KVM client requested 64-bit features\n");
        exit(1);
    }
#else
#error unknown architecture
#endif

    for (unsigned i = 0; i < cpuid->nent; ++i) {
        const struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        if (e->function == 1) {
            // Allow the KVM client to disable MMX/SSE features.
            // E.g., in QEMU, one could do -cpu pentium,-mmx.
            // We don't let control all CPUID features yet.
            uint32_t allowed_bits = CPUID_MMX | CPUID_SSE | CPUID_SSE2;
            uint32_t mask = e->edx & allowed_bits;
            m_env->cpuid.cpuid_features &= ~allowed_bits;
            m_env->cpuid.cpuid_features |= mask;
        }
    }

    return 0;
}

void VCPU::cpuExitSignal(int signum) {
    s_vcpu->m_env->kvm_request_interrupt_window = 1;
    cpu_exit(s_vcpu->m_env);
}

void VCPU::initializeCpuExitSignal() {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = cpuExitSignal;

    if (sigaction(CPU_EXIT_SIGNAL, &act, NULL) < 0) {
        perror("Could not initialize cpu exit signal");
        exit(-1);
    }

    // The KVM client usually blocks all signals on the CPU thread.
    // This interferes with our ability to exit the CPU loop, so we must unblock it.
    union s2e_kvm_sigmask_t mask = m_sigmask;
    sigaddset(&mask.sigset, CPU_EXIT_SIGNAL);
    if (pthread_sigmask(SIG_UNBLOCK, &mask.sigset, NULL) < 0) {
        abort();
    }
}

// Defines which signals are blocked during execution of kvm.
int VCPU::setSignalMask(kvm_signal_mask *mask) {
    // XXX: doesn't seem to matter for typical kvm clients,
    // not sure what the implications of spurious signals are.
    m_sigmask_size = mask->len;
    for (unsigned i = 0; i < mask->len; ++i) {
#ifdef SE_KVM_DEBUG_INTERFACE
        DPRINTF("  signals %#04x\n", mask->sigset[i]);
#endif
        m_sigmask.bytes[i] = mask->sigset[i];
    }
    return 0;
}

void VCPU::coroutineFcn(void *opaque) {
    VCPU *vcpu = reinterpret_cast<VCPU *>(opaque);
    CPUX86State *env = vcpu->m_env;
    auto buffer = vcpu->m_cpuBuffer;

#ifdef SE_KVM_DEBUG_IRQ
    static uint64_t prev_mflags = 0;
#endif

    while (1) {
        libcpu_run_all_timers();

        assert(env->current_tb == NULL);

        // XXX: need to save irq state on state switches
        if (env->kvm_irq != -1) {
            if (env->interrupt_request == 0) {
                DPRINTF("Forcing IRQ\n");
            }
            env->interrupt_request |= CPU_INTERRUPT_HARD;
        }

#ifdef SE_KVM_DEBUG_IRQ
        if (env->interrupt_request & CPU_INTERRUPT_HARD) {
            DPRINTF("Handling IRQ %d req=%#x hflags=%x hflags2=%#x mflags=%#lx tpr=%#x esp=%#lx\n", env->kvm_irq,
                    env->interrupt_request, env->hflags, env->hflags2, (uint64_t) env->mflags, env->v_tpr,
                    (uint64_t) env->regs[R_ESP]);
        }
#endif

        env->kvm_request_interrupt_window |= buffer->request_interrupt_window;

#ifdef SE_KVM_DEBUG_IRQ
        prev_mflags = env->mflags;
        uint64_t prev_eip = env->eip;
#endif

        vcpu->m_cpuStateIsPrecise = false;
        env->exit_request = 0;
        cpu_x86_exec(env);
        vcpu->m_cpuStateIsPrecise = true;
        // DPRINTF("cpu_exec return %#x\n", ret);

#ifdef SE_KVM_DEBUG_IRQ
        bool mflags_changed = (prev_mflags != env->mflags);
        if (mflags_changed) {
            DPRINTF("mflags changed: %lx old=%lx new=%lx reqwnd=%d peip=%lx, eip=%lx\n", (uint64_t) mflags_changed,
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

int VCPU::run(int vcpu_fd) {
    int ret = 0;

    ++g_stats.kvm_runs;

    if (!m_coroutine) {
        m_coroutine = coroutine_create(coroutineFcn, S2E_STACK_SIZE);
        if (!m_coroutine) {
            fprintf(stderr, "Could not create cpu coroutine\n");
            exit(-1);
        }
    }

    if (!m_cpuThreadInited) {
        initializeCpuExitSignal();
        m_cpuThread = pthread_self();
        m_cpuThreadInited = true;
    }

    if (m_kvm->exiting()) {
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    /* Return asap if interrupts can be injected */
    m_cpuBuffer->if_flag = (m_env->mflags & IF_MASK) != 0;
    m_cpuBuffer->apic_base = m_env->v_apic_base;
    m_cpuBuffer->cr8 = m_env->v_tpr;

    m_cpuBuffer->ready_for_interrupt_injection = !m_handlingKvmCallback && m_cpuBuffer->request_interrupt_window &&
                                                 m_cpuBuffer->if_flag && (m_env->kvm_irq == -1);

    if (m_cpuBuffer->ready_for_interrupt_injection) {
#ifdef SE_KVM_DEBUG_IRQ
        DPRINTF("%s early ret for ints\n", __FUNCTION__);
#endif
        m_cpuBuffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        return 0;
    }

    lock();

    m_inKvmRun = true;

#ifdef SE_KVM_DEBUG_RUN
    if (!m_handlingKvmCallback) {
        DPRINTF("%s riw=%d cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
                (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    m_cpuBuffer->exit_reason = -1;

    /**
     * Some KVM clients do not set this when calling kvm_run, although the KVM
     * spec says they should. For now, we patch the clients to pass the right value.
     * Eventually, we'll need to figure out how KVM handles it.
     * Having an incorrect (null) APIC base will cause the APIC to get stuck.
     */
    m_env->v_apic_base = m_cpuBuffer->apic_base;
    m_env->v_tpr = m_cpuBuffer->cr8;

    m_handlingKvmCallback = false;
    m_handlingDeviceState = false;

    coroutine_enter(m_coroutine, this);

    if (m_kvm->exiting()) {
        unlock();
        g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        kill(getpid(), SIGTERM);
        errno = EINTR;
        return -1;
    }

    m_handlingKvmCallback =
        m_cpuBuffer->exit_reason == KVM_EXIT_IO || m_cpuBuffer->exit_reason == KVM_EXIT_MMIO ||
        m_cpuBuffer->exit_reason == KVM_EXIT_FLUSH_DISK || m_cpuBuffer->exit_reason == KVM_EXIT_SAVE_DEV_STATE ||
        m_cpuBuffer->exit_reason == KVM_EXIT_RESTORE_DEV_STATE || m_cpuBuffer->exit_reason == KVM_EXIT_CLONE_PROCESS;

    // Might not be NULL if resuming from an interrupted I/O
    // assert(env->current_tb == NULL);

    m_cpuBuffer->if_flag = (m_env->mflags & IF_MASK) != 0;
    m_cpuBuffer->apic_base = m_env->v_apic_base;
    m_cpuBuffer->cr8 = m_env->v_tpr;

    // KVM specs says that we should also check for request for interrupt window,
    // but that causes missed interrupts.
    m_cpuBuffer->ready_for_interrupt_injection = !m_handlingKvmCallback && m_cpuBuffer->request_interrupt_window &&
                                                 m_cpuBuffer->if_flag && (m_env->kvm_irq == -1);

    if (m_cpuBuffer->exit_reason == -1) {
        if (m_env->halted) {
            m_cpuBuffer->exit_reason = KVM_EXIT_HLT;
        } else if (m_cpuBuffer->ready_for_interrupt_injection) {
            m_cpuBuffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        } else {
            m_cpuBuffer->exit_reason = KVM_EXIT_INTR;
            m_signalPending = false;
        }
    }

#if defined(SE_KVM_DEBUG_HLT)
    if (g_kvm_vcpu_buffer->exit_reason == KVM_EXIT_HLT) {
        trace_s2e_kvm_run(g_kvm_vcpu_buffer, ret);
    }
#endif

    assert(m_cpuBuffer->exit_reason != 1);

#ifdef SE_KVM_DEBUG_RUN
    if (!m_handlingKvmCallback) {
        DPRINTF("%s riw=%d rii=%d er=%#x cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
                g_kvm_vcpu_buffer->ready_for_interrupt_injection, g_kvm_vcpu_buffer->exit_reason,
                (unsigned) g_kvm_vcpu_buffer->cr8);
    }
#endif

    if (m_cpuBuffer->exit_reason == KVM_EXIT_INTR) {
        // This must be set at the very end, because syscalls might
        // overwrite errno.
        errno = EINTR;
        ret = -1;
    }

    assert(ret >= 0 || errno == EINTR);
    assert(m_cpuBuffer->exit_reason != -1);

    m_inKvmRun = false;

    unlock();

    return ret;
}

int VCPU::interrupt(kvm_interrupt *interrupt) {
#ifdef SE_KVM_DEBUG_IRQ
    DPRINTF("IRQ %d env->mflags=%lx hflags=%x hflags2=%x ptr=%#x\n", interrupt->irq, (uint64_t) env->mflags,
            env->hflags, env->hflags2, env->v_tpr);
    fflush(stdout);
#endif

    if (m_env->cr[0] & CR0_PE_MASK) {
        assert(interrupt->irq > (m_env->v_tpr << 4));
    }
    assert(!m_handlingKvmCallback);
    assert(!m_inKvmRun);
    assert(m_env->mflags & IF_MASK);
    assert(!(m_env->interrupt_request & CPU_INTERRUPT_HARD));
    m_env->interrupt_request |= CPU_INTERRUPT_HARD;
    m_env->kvm_irq = interrupt->irq;

    return 0;
}

int VCPU::nmi() {
    m_env->interrupt_request |= CPU_INTERRUPT_NMI;
    return 0;
}

void VCPU::flushDisk(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_FLUSH_DISK;
    m_handlingDeviceState = true;
    coroutine_yield();
}

void VCPU::saveDeviceState(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Saving device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_SAVE_DEV_STATE;
    m_handlingDeviceState = true;
    coroutine_yield();
}

void VCPU::restoreDeviceState(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Restoring device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_RESTORE_DEV_STATE;
    m_handlingDeviceState = 1;
    coroutine_yield();
}

void VCPU::cloneProcess(void) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_CLONE_PROCESS;

    coroutine_yield();

    m_cpuThread = pthread_self();

    if (m_kvm->initTimerThread() < 0) {
        exit(-1);
    }
}

///
/// \brief s2e_kvm_send_cpu_exit_signal sends a signal
/// to the cpu loop thread in order to exit the cpu loop.
///
/// It is important to use a signal that executes on the
/// same thread as the cpu loop in order to avoid race conditions
/// and complex locking.
///
void VCPU::sendExitSignal() {
    if (!m_cpuThreadInited) {
        return;
    }

    if (pthread_kill(m_cpuThread, CPU_EXIT_SIGNAL) < 0) {
        abort();
    }
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
void VCPU::requestExit(void) {
    if (!m_env) {
        return;
    }

#ifdef SE_KVM_DEBUG_RUN
    DPRINTF("s2e_kvm_request_exit\n");
#endif

    sendExitSignal();
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
void VCPU::requestProcessExit(int code) {
    if (logfile) {
        fflush(logfile);
    }

    m_kvm->setExiting();

    if (!m_coroutine) {
        g_original_exit(code);
    }

    if (pthread_self() == m_cpuThread) {
        coroutine_yield();
        abort();
    }

    g_original_exit(code);
}

int VCPU::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = getClock((kvm_clock_data *) arg1);
        } break;

        case KVM_SET_CPUID2: {
            ret = setCPUID2((kvm_cpuid2 *) arg1);
        } break;

        case KVM_SET_SIGNAL_MASK: {
            ret = setSignalMask((kvm_signal_mask *) arg1);
        } break;

        /***********************************************/
        // When the symbolic execution engine needs to take a system snapshot,
        // it must rely on the KVM client to save the device state. That client
        // will typically also save/restore the CPU state. We don't want the client
        // to do that, so in order to not modify the client too much, we ignore
        // the calls to register setters when they are done in the context of
        // device state snapshotting.
        case KVM_SET_REGS: {
            if (m_handlingDeviceState) {
                ret = 0;
            } else {
                ret = setRegisters((kvm_regs *) arg1);
            }
        } break;

        case KVM_SET_FPU: {
            if (m_handlingDeviceState) {
                ret = 0;
            } else {
                ret = setFPU((kvm_fpu *) arg1);
            }
        } break;

        case KVM_SET_SREGS: {
            if (m_handlingDeviceState) {
                ret = 0;
            } else {
                ret = setSystemRegisters((kvm_sregs *) arg1);
            }
        } break;

        case KVM_SET_MSRS: {
            if (m_handlingDeviceState) {
                ret = ((kvm_msrs *) arg1)->nmsrs;
            } else {
                ret = setMSRs((kvm_msrs *) arg1);
            }
        } break;

        case KVM_SET_MP_STATE: {
            if (m_handlingDeviceState) {
                ret = 0;
            } else {
                ret = setMPState((kvm_mp_state *) arg1);
            }
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            if (m_handlingDeviceState) {
                // Poison the returned registers to make sure we don't use
                // it again by accident. We can't just fail the call because
                // the client needs it to save the cpu state (that we ignore).
                memset((void *) arg1, 0xff, sizeof(kvm_regs));
                ret = 0;
            } else {
                ret = getRegisters((kvm_regs *) arg1);
            }
        } break;

        case KVM_GET_FPU: {
            ret = getFPU((kvm_fpu *) arg1);
        } break;

        case KVM_GET_SREGS: {
            ret = getSystemRegisters((kvm_sregs *) arg1);
        } break;

        case KVM_GET_MSRS: {
            ret = getMSRs((kvm_msrs *) arg1);
        } break;

        case KVM_GET_MP_STATE: {
            ret = getMPState((kvm_mp_state *) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return run(fd);
        } break;

        case KVM_INTERRUPT: {
            ret = interrupt((kvm_interrupt *) arg1);
        } break;

        case KVM_NMI: {
            ret = nmi();
        } break;

        default: {
            fprintf(stderr, "libs2e: unknown KVM VCPU IOCTL vcpu %d request=%#x arg=%#" PRIx64 " ret=%#x\n", fd,
                    request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}

void *VCPU::sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    int real_size = S2EKVM::getVCPUMemoryMapSize();
    assert(real_size == len);
    assert(m_cpuBuffer);

    return m_cpuBuffer;
}

void VCPU::flushTlb() {
    tlb_flush(m_env, 1);
}
} // namespace kvm
} // namespace s2e

extern "C" {

// TODO: pass an interface to S2E instead of having these here
void s2e_kvm_flush_disk(void) {
    s2e::kvm::s_vcpu->flushDisk();
}

void s2e_kvm_save_device_state(void) {
    s2e::kvm::s_vcpu->saveDeviceState();
}

void s2e_kvm_restore_device_state(void) {
    s2e::kvm::s_vcpu->restoreDeviceState();
}

void s2e_kvm_clone_process(void) {
    s2e::kvm::s_vcpu->cloneProcess();
}
}
