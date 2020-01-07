/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2016 Cyberhaven
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdbool.h>

/* Needed early for CONFIG_BSD etc. */
#include <cpu/config-host.h>

#include <cpu/cpus.h>
#include "cpu.h"
#include "timer.h"

#ifdef CONFIG_LINUX

#include <sys/prctl.h>

#ifndef PR_MCE_KILL
#define PR_MCE_KILL 33
#endif

#ifndef PR_MCE_KILL_SET
#define PR_MCE_KILL_SET 1
#endif

#ifndef PR_MCE_KILL_EARLY
#define PR_MCE_KILL_EARLY 1
#endif

#endif /* CONFIG_LINUX */

/***********************************************************/
/* guest cycle counter */

TimersState timers_state = {
    .cpu_ticks_prev = 0,
    .cpu_ticks_offset = 0,
    .cpu_clock_offset = 0,
    .cpu_ticks_enabled = 0,

    .cpu_clock_scale_factor = 1,

    .cpu_clock_prev = 0,
    .cpu_clock_prev_scaled = 0,
};

/* return the host CPU cycle counter and handle stop/restart */
int64_t cpu_get_ticks(void) {
    if (!timers_state.cpu_ticks_enabled) {
        return timers_state.cpu_ticks_offset;
    } else {
        int64_t ticks;
        ticks = cpu_get_real_ticks();
        if (timers_state.cpu_ticks_prev > ticks) {
            /* Note: non increasing ticks may happen if the host uses
               software suspend */
            timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        }
        timers_state.cpu_ticks_prev = ticks;
        return ticks + timers_state.cpu_ticks_offset;
    }
}

/* return the host CPU monotonic timer and handle stop/restart */
int64_t cpu_get_clock(void) {
    if (!timers_state.cpu_ticks_enabled) {
        if (timers_state.cpu_clock_scale_factor > 1) {
            return timers_state.cpu_clock_prev_scaled;
        } else {
            return timers_state.cpu_clock_offset;
        }
    } else {
        if (timers_state.cpu_clock_scale_factor > 1) {
            /* Compute how much real time elapsed since last request */
            int64_t cur_clock = get_clock() + timers_state.cpu_clock_offset;
            int64_t increment = cur_clock - timers_state.cpu_clock_prev;
            assert(increment > 0);

            /* Slow the clock down according to the scale */
            int64_t result = timers_state.cpu_clock_prev_scaled + increment / timers_state.cpu_clock_scale_factor;

            /* Check that monotonicity is not violated */
            assert(cur_clock >= 0 && cur_clock >= timers_state.cpu_clock_prev);
            assert(result >= 0 && result >= timers_state.cpu_clock_prev_scaled);

            /* Save the current time stamp */
            timers_state.cpu_clock_prev_scaled = result;
            timers_state.cpu_clock_prev = cur_clock;

            return result;
        } else {
            return get_clock() + timers_state.cpu_clock_offset;
        }
    }
}

/* enable cpu_get_ticks() */
void cpu_enable_ticks(void) {
    if (!timers_state.cpu_ticks_enabled) {
        int64_t cur_clock = get_clock();

        timers_state.cpu_ticks_offset -= cpu_get_real_ticks();
        timers_state.cpu_clock_offset -= cur_clock;
        timers_state.cpu_ticks_enabled = 1;

        if (timers_state.cpu_clock_scale_factor > 1) {
            /* Fast-forward suspended clocks */
            timers_state.cpu_clock_prev = cur_clock + timers_state.cpu_clock_offset;
            timers_state.cpu_clock_prev_scaled = timers_state.cpu_clock_prev;
        }
    }
}

/* disable cpu_get_ticks() : the clock is stopped. You must not call
   cpu_get_ticks() after that.  */
void cpu_disable_ticks(void) {
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset = cpu_get_ticks();
        timers_state.cpu_clock_offset = cpu_get_clock();
        timers_state.cpu_ticks_enabled = 0;
    }
}

/*
 * Allows symbolic execution engines to slow down the VM clock while
 * executing slow operations (e.g., constraint solving).
 *
 * Assumes that rt_clock == vm_clock.
 * scale == 1 is the normal speed.
 */
void cpu_enable_scaling(int scale) {
    assert(scale >= 1);

    if (timers_state.cpu_clock_scale_factor == 1) {
        timers_state.cpu_clock_prev = cpu_get_clock();
        timers_state.cpu_clock_prev_scaled = timers_state.cpu_clock_prev;
    }

    timers_state.cpu_clock_scale_factor = scale;
}

void cpu_synchronize_all_post_init(void) {
    // Not needed
}

void qemu_init_cpu_loop(void) {
}

void run_on_cpu(CPUArchState *env, void (*func)(void *data), void *data) {
    assert(false && "Not imlemented");
}

int qemu_cpu_is_self(void *_env) {
    assert(false && "Not imlemented");
    return 0;
}

void qemu_mutex_lock_iothread(void) {
    assert(false && "Not imlemented");
}

void qemu_mutex_unlock_iothread(void) {
    assert(false && "Not imlemented");
}

void pause_all_vcpus(void) {
    assert(false && "Not imlemented");
}

void resume_all_vcpus(void) {
    assert(false && "Not imlemented");
}

static void qemu_tcg_init_vcpu(void *_env) {
    /**
     * XXX: for now, the stuff below is not needed.
     * It's replaced by the loop in the KVM wrapper interface.
     */
    return;
}

void qemu_init_vcpu(void *_env) {
    CPUArchState *env = _env;

    env->cpuid.nr_cores = 1;
    env->cpuid.nr_threads = 1;

    if (tcg_enabled()) {
        qemu_tcg_init_vcpu(env);
    } else {
        assert(false && "Not imlemented");
    }
}

void cpu_stop_current(void) {
    assert(false && "Not imlemented");
}

void vm_stop() {
    assert(false && "Not imlemented");
}

/* does a state transition even if the VM is already stopped,
   current state is forgotten forever */
void vm_stop_force_state() {
    assert(false && "Not imlemented");
}
