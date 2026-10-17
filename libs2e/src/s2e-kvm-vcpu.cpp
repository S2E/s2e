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
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <cpu/kvm.h>
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

// #define SE_KVM_DEBUG_IRQ
// #define DEBUG_LOCKS

extern "C" {
void tcg_register_thread(void);
int cpu_get_pic_interrupt(CPUX86State *env);
}

#include "hw/lapic.h"
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

int cpu_get_pic_interrupt(CPUX86State *env) {
    // The interrupt injected by the kvm client goes first, like in KVM.
    // An interrupt of the lapic keeps its own request and is taken next.
    if (env->kvm_irq >= 0) {
        assert(env->interrupt_request & CPU_INTERRUPT_HARD_EXT);
        auto irq = env->kvm_irq;
        env->kvm_irq = -1;
        env->interrupt_request &= ~CPU_INTERRUPT_HARD_EXT;
        return irq;
    }

    assert(!(env->interrupt_request & CPU_INTERRUPT_HARD_EXT));

    auto vcpu = s2e::kvm::VCPU::current();
    if (auto apic = vcpu->lapic()) {
        // The vector moves to ISR, which masks what is left in IRR until the EOI
        env->interrupt_request &= ~CPU_INTERRUPT_HARD_APIC;
        return apic->get_interrupt();
    }

    libcpu_log_mask(CPU_LOG_KVM, "Interrupt requested but LAPIC is not initialized\n");
    abort();
}

namespace s2e {
namespace kvm {

kvm_run *g_kvm_vcpu_buffer;
static VCPU *s_vcpu;

///
/// KVM_RUN and KVM_SWITCH_STATE_CONTINUE set the exit reason to -1 before they
/// enter the coroutine, so -1 means that the client saw the previous exit.
/// Some exits are not delivered right away (e.g., KVM_EXIT_IOAPIC_EOI waits
/// until the cpu loop exits). Any other exit in between would overwrite them,
/// and the client would never see them.
///
void set_exit_reason(int reason) {
    auto prev = g_kvm_vcpu_buffer->exit_reason;
    if (prev != (decltype(prev)) -1) {
        fprintf(stderr,
                "libs2e: exit reason %d overwrites exit reason %d before the kvm client saw it "
                "(eoi.vector=%#x eip=%#" PRIx64 ")\n",
                reason, (int) prev, g_kvm_vcpu_buffer->eoi.vector, (uint64_t) g_cpu_env->eip);
        abort();
    }

    g_kvm_vcpu_buffer->exit_reason = reason;
}

// We may need a very large stack in case of deep expressions.
// Default stack is a few megabytes, it's not enough.
static const uint64_t S2E_STACK_SIZE = 1024 * 1024 * 1024;

VCPU::VCPU(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm, kvm_run *buffer) {
    s_vcpu = this;
    m_kvm = kvm;
    m_vm = vm;
    m_cpuBuffer = buffer;
    assert(!g_kvm_vcpu_buffer);
    g_kvm_vcpu_buffer = buffer;

    tcg_register_thread();

    m_onExit = g_syscalls.onExit.connect(sigc::mem_fun(*this, &VCPU::requestProcessExit));

    if (initCpuLock() < 0) {
        exit(-1);
    }

    init_halt_fd();

    /* We want the default libcpu CPU, not the KVM one. */
    m_env = g_cpu_env = env = cpu_x86_init(&m_kvm->getCpuid());

    if (!m_env) {
        libcpu_log_mask(CPU_LOG_KVM, "Could not create cpu\n");
        exit(-1);
    }

    m_vapic.set_apic_base(0xfee00000);
    m_env->size = sizeof(*m_env);

#ifdef CONFIG_SYMBEX
    s2e_register_cpu(m_env);
#endif

    do_cpu_init(m_env);

    cpu_exec_init_all();
}

VCPU::~VCPU() {
    m_onExit.disconnect();

    if (m_halt_fd >= 0) {
        close(m_halt_fd);
    }
}

VCPU *VCPU::current() {
    return s_vcpu;
}

std::shared_ptr<VCPU> VCPU::create(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm) {
    size_t size = S2EKVM::getVCPUMemoryMapSize();
    auto buffer = (kvm_run *) ::mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!buffer) {
        return nullptr;
    }

    return std::shared_ptr<VCPU>(new VCPU(kvm, vm, buffer));
}

void VCPU::create_lapic() {
    m_lapic = std::make_shared<LocalApic>(
        LocalApic::APIC_DEFAULT_BASE, [this](int mask, bool reset) { interrupt(mask, reset); },
        [this]() { request_exit_cpu_loop(); });
    m_vm->dev_mgr().register_device(LocalApic::APIC_DEFAULT_BASE, LocalApic::APIC_SIZE, m_lapic);
}

uint8_t VCPU::get_tpr() const {
    if (m_lapic) {
        return m_lapic->get_tpr();
    }
    return m_vapic.get_tpr();
}

void VCPU::set_tpr(uint8_t val) {
    if (m_lapic) {
        m_lapic->set_tpr(val);
    } else {
        m_vapic.set_tpr(val);
    }
}

uint64_t VCPU::get_apic_base() const {
    if (m_lapic) {
        return m_lapic->get_apic_base();
    }
    return m_vapic.get_apic_base();
}

void VCPU::set_apic_base(uint64_t val) {
    if (!m_lapic) {
        m_vapic.set_apic_base(val);
        return;
    }

    // The kvm client rewrites the same base every time it sets the system registers
    uint64_t old_base = m_lapic->get_apic_base();
    m_lapic->set_apic_base(val);
    if (m_lapic->get_apic_base() == old_base) {
        return;
    }

    if (!m_vm->dev_mgr().rebase_device(val & ~0xfffULL, m_lapic)) {
        fprintf(stderr, "Failed to rebase LAPIC to %#" PRIx64 "\n", val);
        abort();
    }
}

int VCPU::initCpuLock(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);

#if DEBUG_LOCKS
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif

    int ret = pthread_mutex_init(&m_cpuLock, &attr);
    if (ret < 0) {
        fprintf(stderr, "Could not init cpu lock\n");
    }

    pthread_mutexattr_destroy(&attr);
    return ret;
}

void VCPU::lock() {
    auto ret = pthread_mutex_lock(&m_cpuLock);
    if (ret != 0) {
        fprintf(stderr, "Could not lock cpu: %d\n", ret);
        abort();
    }
}

void VCPU::unlock() {
    auto ret = pthread_mutex_unlock(&m_cpuLock);
    if (ret != 0) {
        fprintf(stderr, "Could not unlock cpu: %d\n", ret);
        abort();
    }
}

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

// Defines which signals are blocked during execution of kvm.
int VCPU::setSignalMask(kvm_signal_mask *mask) {
    // XXX: doesn't seem to matter for typical kvm clients,
    // not sure what the implications of spurious signals are.
    m_sigmask_size = mask->len;
    for (unsigned i = 0; i < mask->len; ++i) {
        libcpu_log_mask(CPU_LOG_KVM, "  signals %#04x\n", mask->sigset[i]);
        m_sigmask.bytes[i] = mask->sigset[i];
    }
    return 0;
}

void VCPU::coroutineFcn(void *opaque) {
    VCPU *vcpu = reinterpret_cast<VCPU *>(opaque);
    CPUX86State *env = vcpu->m_env;
    auto buffer = vcpu->m_cpuBuffer;

    while (1) {
        if (!vcpu->m_task_runner.run_on_thread()) {
            abort();
        }

        libcpu_run_all_timers();

        assert(env->current_tb == NULL);

        env->kvm_request_interrupt_window |= buffer->request_interrupt_window;

        vcpu->m_cpuStateIsPrecise = false;
        cpu_x86_exec(env);
        vcpu->m_cpuStateIsPrecise = true;

        assert(env->current_tb == NULL);

        env->exception_index = 0;
        coroutine_yield();
    }
}

///
/// \brief Tells the kvm client that the process is exiting
///
/// The client gets the same result as when a signal interrupts KVM_RUN
/// and terminates when it handles the signal.
///
/// \return the return value of the ioctl
///
int VCPU::interrupt_exiting_process() {
    m_cpuBuffer->exit_reason = KVM_EXIT_INTR;
    kill(getpid(), SIGTERM);

    // This must be set at the very end, because syscalls might overwrite errno
    errno = EINTR;
    return -1;
}

///
/// \brief Tells whether the kvm client may inject an interrupt with KVM_INTERRUPT
///
/// The cpu must be able to take the interrupt at the next instruction, as in KVM:
/// interrupts are enabled and there is no interrupt shadow (the instruction after
/// sti or mov ss). The previous injection must also have been taken.
///
bool VCPU::ready_for_interrupt_injection() const {
    if (m_handlingKvmCallback || !m_cpuBuffer->request_interrupt_window) {
        return false;
    }

    if (!(m_env->mflags & IF_MASK) || (m_env->hflags & HF_INHIBIT_IRQ_MASK)) {
        return false;
    }

    return m_env->kvm_irq == -1;
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
        m_cpuThread = pthread_self();
        m_cpuThreadInited = true;
    }

    if (m_kvm->exiting()) {
        return interrupt_exiting_process();
    }

    /* Return asap if interrupts can be injected */
    m_cpuBuffer->if_flag = (m_env->mflags & IF_MASK) != 0;
    m_cpuBuffer->ready_for_interrupt_injection = ready_for_interrupt_injection();

    if (m_cpuBuffer->ready_for_interrupt_injection) {
        libcpu_log_mask(CPU_LOG_KVM, "%s early ret for ints\n", __FUNCTION__);
        m_cpuBuffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        return 0;
    }

    lock();

    m_inKvmRun = true;

    if (!m_handlingKvmCallback) {
        libcpu_log_mask(CPU_LOG_KVM, "%s riw=%d cr8=%#x\n", __FUNCTION__, g_kvm_vcpu_buffer->request_interrupt_window,
                        (unsigned) g_kvm_vcpu_buffer->cr8);
    }

    m_cpuBuffer->exit_reason = -1;

    if (!m_lapic) {
        // The kvm client only keeps these up to date when it emulates the apic itself
        assert(m_cpuBuffer->apic_base);
        m_vapic.set_apic_base(m_cpuBuffer->apic_base);
        m_vapic.set_tpr(m_cpuBuffer->cr8 << 4);
    }

    m_handlingKvmCallback = false;
    m_handlingDeviceState = false;

    coroutine_enter(m_coroutine, this);

    if (m_kvm->exiting()) {
        unlock();
        return interrupt_exiting_process();
    }

    m_handlingKvmCallback = m_cpuBuffer->exit_reason == KVM_EXIT_IO || m_cpuBuffer->exit_reason == KVM_EXIT_MMIO ||
                            m_cpuBuffer->exit_reason == KVM_EXIT_SWITCH_STATE ||
                            m_cpuBuffer->exit_reason == KVM_EXIT_CLONE_PROCESS ||
                            m_cpuBuffer->exit_reason == KVM_EXIT_IOAPIC_EOI;

    // Might not be NULL if resuming from an interrupted I/O
    // assert(env->current_tb == NULL);

    m_cpuBuffer->if_flag = (m_env->mflags & IF_MASK) != 0;
    m_cpuBuffer->apic_base = get_apic_base();
    m_cpuBuffer->cr8 = get_tpr() >> 4;

    m_cpuBuffer->ready_for_interrupt_injection = ready_for_interrupt_injection();

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

    if (!m_handlingKvmCallback) {
        libcpu_log_mask(CPU_LOG_KVM, "%s riw=%d rii=%d er=%#x cr8=%#x\n", __FUNCTION__,
                        g_kvm_vcpu_buffer->request_interrupt_window, g_kvm_vcpu_buffer->ready_for_interrupt_injection,
                        g_kvm_vcpu_buffer->exit_reason, (unsigned) g_kvm_vcpu_buffer->cr8);
    }

    if (m_cpuBuffer->exit_reason == KVM_EXIT_INTR) {
        // This must be set at the very end, because syscalls might
        // overwrite errno.
        errno = EINTR;
        ret = -1;
    }

    assert(ret >= 0 || errno == EINTR);
    assert(m_cpuBuffer->exit_reason != -1);

    // A client that does not emulate the lapic expects KVM_RUN to block while
    // the cpu is halted. It would otherwise call us back in a busy loop.
    bool wait = m_lapic && m_cpuBuffer->exit_reason == KVM_EXIT_HLT;

    // The timers must be read while holding the cpu lock
    int64_t delay = wait ? libcpu_get_next_timer_delay_ns() : -1;

    m_inKvmRun = false;

    unlock();

    if (wait) {
        wait_while_halted(delay);
    }

    return ret;
}

void VCPU::init_halt_fd() {
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Could not create halt eventfd\n");
        exit(-1);
    }

    // A signal handler may use the descriptor at any time, it must always be valid
    int old_fd = m_halt_fd;
    m_halt_fd = fd;
    if (old_fd >= 0) {
        close(old_fd);
    }
}

void VCPU::wait_while_halted(int64_t delay) {
    static constexpr int64_t NS_PER_SEC = 1000 * 1000 * 1000;

    struct pollfd pfd = {.fd = m_halt_fd, .events = POLLIN, .revents = 0};
    struct timespec ts = {.tv_sec = delay / NS_PER_SEC, .tv_nsec = delay % NS_PER_SEC};

    // Like KVM_RUN, wait with the signal mask of the client, so that the signals it uses
    // to kick the cpu interrupt the wait.
    const sigset_t *mask = m_sigmask_size ? &m_sigmask.sigset : nullptr;

    // request_exit_cpu_loop sets its flag and then checks ours, we do the opposite.
    // Whatever the interleaving, either we see the request or the requester sees
    // that it must wake us up. This also holds when the requester is a signal handler
    // that interrupts this thread right before the wait starts, so there is no need
    // to bound the wait when there are no timers.
    m_halt_waiting = true;
    if (!m_exit_requested) {
        ppoll(&pfd, 1, delay < 0 ? nullptr : &ts, mask);
    }
    m_halt_waiting = false;

    // KVM_RUN returns to the client after this, which satisfies all the requests so far
    m_exit_requested = false;

    uint64_t val;
    if (read(m_halt_fd, &val, sizeof(val)) < 0 && errno != EAGAIN && errno != EINTR) {
        fprintf(stderr, "Could not read halt eventfd: %s\n", strerror(errno));
    }
}

int VCPU::interrupt(kvm_interrupt *interrupt) {
    libcpu_log_mask(CPU_LOG_KVM, "IRQ %d env->mflags=%lx hflags=%x hflags2=%x ptr=%#x\n", interrupt->irq,
                    (uint64_t) env->mflags, env->hflags, env->hflags2, get_tpr());

    assert(!m_handlingKvmCallback);
    assert(!m_inKvmRun);
    assert(m_env->mflags & IF_MASK);

    // Only a previous injection that the cpu did not take yet prevents a new one.
    // An interrupt of the lapic may be pending at the same time, it has its own request.
    if (m_env->kvm_irq >= 0) {
        libcpu_log_mask(CPU_LOG_KVM, "Interrupt already pending, cannot inject IRQ %d\n", interrupt->irq);
        return -EEXIST;
    }

    assert(!(m_env->interrupt_request & CPU_INTERRUPT_HARD_EXT));

    // External interrupts are not subject to the tpr of the in-kernel lapic
    if (!m_lapic && (m_env->cr[0] & CR0_PE_MASK)) {
        assert(interrupt->irq > get_tpr());
    }

    m_env->interrupt_request |= CPU_INTERRUPT_HARD_EXT;
    m_env->kvm_irq = interrupt->irq;

    return 0;
}

int VCPU::nmi() {
    m_env->interrupt_request |= CPU_INTERRUPT_NMI;
    return 0;
}

void VCPU::begin_state_switch() {
    assert(!m_switching_state);
    m_switching_state = true;
}

void VCPU::end_state_switch() {
    assert(m_switching_state);

    if (m_client_switching_state) {
        // Let the client leave its handler and release its lock
        set_exit_reason(KVM_EXIT_SWITCH_STATE);
        g_kvm_vcpu_buffer->switch_state.step = KVM_SWITCH_STATE_DONE;
        coroutine_yield();
        m_client_switching_state = false;
    }

    m_switching_state = false;
}

///
/// \brief Asks the kvm client to perform a step of a state switch
///
/// The first step of a switch returns from KVM_RUN with KVM_EXIT_SWITCH_STATE.
/// The client then holds its global lock and gets the next steps when
/// it calls KVM_SWITCH_STATE_CONTINUE, until end_state_switch.
///
void VCPU::run_state_switch_step(unsigned step) {
    if (!m_switching_state) {
        // The client would never release its lock
        fprintf(stderr, "libs2e: state switch step %u requested outside of a state switch\n", step);
        abort();
    }

    set_exit_reason(KVM_EXIT_SWITCH_STATE);
    g_kvm_vcpu_buffer->switch_state.step = step;
    m_handlingDeviceState = true;
    m_client_switching_state = true;
    coroutine_yield();
}

int VCPU::continue_state_switch() {
    if (!m_client_switching_state) {
        errno = EINVAL;
        return -1;
    }

    lock();
    m_inKvmRun = true;

    // The client saw the previous step
    m_cpuBuffer->exit_reason = -1;

    coroutine_enter(m_coroutine, this);

    m_inKvmRun = false;
    unlock();

    if (m_kvm->exiting()) {
        return interrupt_exiting_process();
    }

    // The guest does not run during a state switch
    assert(m_cpuBuffer->exit_reason == KVM_EXIT_SWITCH_STATE);

    return 0;
}

void VCPU::flushDisk(void) {
    run_state_switch_step(KVM_SWITCH_STATE_FLUSH_DISK);
}

void VCPU::saveDeviceState(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Saving device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    run_state_switch_step(KVM_SWITCH_STATE_SAVE_DEV_STATE);
}

void VCPU::restoreDeviceState(void) {
#ifdef SE_KVM_DEBUG_DEV_STATE
    libcpu_log("Restoring device state\n");
    log_cpu_state(g_cpu_env, 0);
#endif
    run_state_switch_step(KVM_SWITCH_STATE_RESTORE_DEV_STATE);
}

void VCPU::cloneProcess(void) {
    set_exit_reason(KVM_EXIT_CLONE_PROCESS);

    coroutine_yield();

    m_cpuThread = pthread_self();

    // The parent and the child must not steal each other's wake up requests
    init_halt_fd();
}

void VCPU::request_exit_cpu_loop() {
    cpu_exit(m_env);

    // The cpu only needs a wake up when it sleeps in wait_while_halted. In all the other
    // cases, it finds the flag before it goes to sleep. Keep the system call out of
    // the way of the callers that are on a hot path (dma, irq lines, etc.).
    m_exit_requested = true;
    if (!m_halt_waiting) {
        return;
    }

    // This may run in a signal handler, preserve errno for the interrupted code
    int saved_errno = errno;
    uint64_t val = 1;
    if (write(m_halt_fd, &val, sizeof(val)) < 0 && errno != EAGAIN) {
        // The cpu would sleep forever
        abort();
    }
    errno = saved_errno;
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
        // it relies on the KVM client to save and restore the device state.
        // The engine manages the entire cpu state itself, concrete and symbolic.
        // The client keeps its own copy of the concrete cpu state and writes it
        // back when it handles a snapshot. In order to not modify the client too
        // much, we ignore the calls to register setters when they are done in the
        // context of device state snapshotting. We only check that the client
        // has the same concrete state as the engine.
        //
        // The lapic is a device, the client restores it with KVM_SET_LAPIC and
        // the apic base msr. These must always be applied.
        case KVM_SET_REGS: {
            if (m_handlingDeviceState) {
                check_registers((kvm_regs *) arg1);
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

        case KVM_SET_XSAVE: {
            if (m_handlingDeviceState) {
                ret = 0;
            } else {
                libcpu_log_mask(CPU_LOG_KVM, "set_xsave\n");
                ret = setXSAVE((kvm_xsave *) arg1);
            }
        } break;

        case KVM_SET_SREGS: {
            if (m_handlingDeviceState) {
                check_system_registers((kvm_sregs *) arg1);
                ret = 0;
            } else {
                ret = setSystemRegisters((kvm_sregs *) arg1);
            }
        } break;

        case KVM_SET_MSRS: {
            if (m_handlingDeviceState) {
                ret = set_device_state_msrs((kvm_msrs *) arg1);
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

        case KVM_SET_DEBUGREGS: {
            if (m_handlingDeviceState) {
                check_debug_registers((kvm_debugregs *) arg1);
                ret = 0;
            } else {
                ret = setDebugRegs((kvm_debugregs *) arg1);
            }
        } break;

        /***********************************************/
        case KVM_GET_REGS: {
            if (m_handlingDeviceState) {
                // The general purpose registers and the arithmetic flags may be
                // symbolic. Poison them to make sure we don't use them again by
                // accident. The client only gets the concrete registers, it needs
                // the system flags to interpret the segment registers.
                auto regs = (kvm_regs *) arg1;
                memset(regs, 0xff, sizeof(*regs));
                regs->rip = m_env->eip;
                regs->rflags = m_env->mflags;
                ret = 0;
            } else {
                ret = getRegisters((kvm_regs *) arg1);
            }
        } break;

        case KVM_GET_FPU: {
            if (m_handlingDeviceState) {
                // The fpu state may be symbolic, reading it would concretize it.
                // See KVM_GET_XSAVE for why it is fine to poison it.
                memset((void *) arg1, 0xff, sizeof(kvm_fpu));
                ret = 0;
            } else {
                ret = getFPU((kvm_fpu *) arg1);
            }
        } break;

        case KVM_GET_XSAVE: {
            if (m_handlingDeviceState) {
                // The fpu state may be symbolic, reading it would concretize it.
                // Poison the entire area instead, including the xsave header and
                // the control words. This requires a client that stores the area
                // in its snapshot without validating it. The poison never comes back
                // to the guest: we stay in device state mode until the next KVM_RUN
                // and ignore KVM_SET_XSAVE and KVM_SET_FPU until then.
                memset((void *) arg1, 0xff, sizeof(kvm_xsave));
                ret = 0;
            } else {
                ret = getXSAVE((kvm_xsave *) arg1);
            }
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

        case KVM_GET_LAPIC: {
            // Interrupts raised by other threads are queued until the next KVM_RUN.
            // Deliver them now, otherwise they are lost if the client saves the
            // state (e.g., savevm) before running the cpu again.
            if (!m_task_runner.run_on_thread()) {
                abort();
            }
            m_lapic->get_lapic((kvm_lapic_state *) arg1);
            ret = 0;
        } break;

        case KVM_SET_LAPIC: {
            // Interrupts queued before this call belong to the lapic state that is
            // being overwritten (e.g., loadvm). Deliver them to that state now, so
            // that they are not delivered to the new one on the next KVM_RUN. This
            // only discards fixed interrupts, an nmi or smi stays pending in the cpu.
            //
            // There are no such interrupts when the engine switches states. The client
            // holds its global lock from the save of the old state to the restore of
            // the new one (KVM_EXIT_SWITCH_STATE), its devices cannot raise interrupts
            // in between.
            if (!m_task_runner.run_on_thread()) {
                abort();
            }
            m_lapic->set_lapic((kvm_lapic_state *) arg1);
            ret = 0;
        } break;

        case KVM_GET_DEBUGREGS: {
            ret = getDebugRegs((kvm_debugregs *) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return run(fd);
        } break;

        case KVM_SWITCH_STATE_CONTINUE: {
            return continue_state_switch();
        } break;

        case KVM_INTERRUPT: {
            ret = interrupt((kvm_interrupt *) arg1);
        } break;

        case KVM_NMI: {
            ret = nmi();
        } break;

        case KVM_SET_VAPIC_ADDR: {
            const auto data = (kvm_vapic_addr *) arg1;
            libcpu_log_mask(CPU_LOG_KVM, "Setting VAPIC address to %#" PRIx64 "\n", (uint64_t) data->vapic_addr);
            // The vapic address is not the apic base. The in-kernel lapic does not
            // use it, its base is only set through the msr.
            if (!m_lapic) {
                m_vapic.set_apic_base(data->vapic_addr);
            }
            ret = 0;
        } break;

        case KVM_GET_VCPU_EVENTS: {
            libcpu_log_mask(CPU_LOG_KVM, "Not implemented KVM_GET_VCPU_EVENTS\n");
            ret = 0;
        } break;

        case KVM_SET_VCPU_EVENTS: {
            libcpu_log_mask(CPU_LOG_KVM, "Not implemented KVM_SET_VCPU_EVENTS\n");
            ret = 0;
        } break;

        case KVM_GET_STATS_FD: {
            libcpu_log_mask(CPU_LOG_KVM, "Not implemented KVM_GET_STATS_FD\n");
            ret = open("/dev/null", O_RDWR);
        } break;

        case KVM_X86_SETUP_MCE: {
            libcpu_log_mask(CPU_LOG_KVM, "Not implemented KVM_X86_SETUP_MCE\n");
            ret = 0;
        } break;

        case KVM_TPR_ACCESS_REPORTING: {
            const auto data = (kvm_tpr_access_ctl *) arg1;
            if (data->enabled) {
                printf("libs2e: KVM client requested TPR access reporting, but it's not implemented\n");
                ret = -1;
            } else {
                ret = 0;
            }
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

void VCPU::interrupt(int mask, bool reset) {
#ifdef CONFIG_SYMBEX
    libcpu_log_mask(CPU_LOG_KVM, "interrupt: mask=%#x reset=%d scale=%d\n", mask, reset,
                    *g_sqi.exec.clock_scaling_factor);
#endif
    cpu_exit(m_env);

    // The request of an interrupt injected with KVM_INTERRUPT belongs to the kvm client
    assert(!(mask & CPU_INTERRUPT_HARD_EXT));

    if (reset) {
        m_env->interrupt_request &= ~mask;
    } else {
        m_env->interrupt_request |= mask;
    }
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

void s2e_kvm_begin_state_switch(void) {
    s2e::kvm::s_vcpu->begin_state_switch();
}

void s2e_kvm_end_state_switch(void) {
    s2e::kvm::s_vcpu->end_state_switch();
}

void s2e_kvm_clone_process(void) {
    s2e::kvm::s_vcpu->cloneProcess();
}
}
