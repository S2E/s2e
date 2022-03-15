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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "timer.h"

/***********************************************************/
/* timers */

#define QEMU_CLOCK_REALTIME 0
#define QEMU_CLOCK_VIRTUAL  1
#define QEMU_CLOCK_HOST     2

struct CPUClock {
    int type;
    int enabled;

    CPUTimer *active_timers;

    int64_t last;
};

struct CPUTimer {
    CPUClock *clock;
    int64_t expire_time; /* in nanoseconds */
    int scale;
    CPUTimerCB *cb;
    void *opaque;
    struct CPUTimer *next;

    int delayed;
    uint64_t delay_value;
};

static bool libcpu_timer_expired_ns(CPUTimer *timer_head, int64_t current_time) {
    return timer_head && (timer_head->expire_time <= current_time);
}

CPUClock *rt_clock;
CPUClock *vm_clock;
CPUClock *host_clock;

static CPUClock *qemu_new_clock(int type) {
    CPUClock *clock;

    clock = g_malloc0(sizeof(CPUClock));
    clock->type = type;
    clock->enabled = 1;
    clock->last = INT64_MIN;
    return clock;
}

CPUTimer *libcpu_new_timer(CPUClock *clock, int scale, CPUTimerCB *cb, void *opaque) {
    CPUTimer *ts;

    ts = g_malloc0(sizeof(CPUTimer));
    ts->clock = clock;
    ts->cb = cb;
    ts->opaque = opaque;
    ts->scale = scale;
    return ts;
}

void libcpu_free_timer(CPUTimer *ts) {
    g_free(ts);
}

/* stop a timer, but do not dealloc it */
void libcpu_del_timer(CPUTimer *ts) {
    CPUTimer **pt, *t;

    /* NOTE: this code must be signal safe because
       libcpu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for (;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            *pt = t->next;
            break;
        }
        pt = &t->next;
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void libcpu_mod_timer_ns(CPUTimer *ts, int64_t expire_time) {
    CPUTimer **pt, *t;

    libcpu_del_timer(ts);

    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       libcpu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for (;;) {
        t = *pt;
        if (!libcpu_timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }
    ts->expire_time = expire_time;
    ts->next = *pt;
    *pt = ts;
}

void libcpu_mod_timer(CPUTimer *ts, int64_t expire_time) {
    libcpu_mod_timer_ns(ts, expire_time * ts->scale);
}

int libcpu_timer_expired(CPUTimer *timer_head, int64_t current_time) {
    return libcpu_timer_expired_ns(timer_head, current_time * timer_head->scale);
}

void libcpu_run_timers(CPUClock *clock) {
    CPUTimer **ptimer_head, *ts;
    int64_t current_time;

    if (!clock->enabled)
        return;

    current_time = libcpu_get_clock_ns(clock);
    ptimer_head = &clock->active_timers;
    for (;;) {
        ts = *ptimer_head;
        if (!libcpu_timer_expired_ns(ts, current_time)) {
            break;
        }
        /* remove timer from the list before calling the callback */
        *ptimer_head = ts->next;
        ts->next = NULL;

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
    }
}

int64_t libcpu_get_clock_ns(CPUClock *clock) {
    int64_t now;

    switch (clock->type) {
        case QEMU_CLOCK_REALTIME:
            return get_clock();
        default:
        case QEMU_CLOCK_VIRTUAL:
            return cpu_get_clock();
        case QEMU_CLOCK_HOST:
            now = get_clock_realtime();
            clock->last = now;
            return now;
    }
}

void init_clocks(void) {
    rt_clock = qemu_new_clock(QEMU_CLOCK_REALTIME);
    vm_clock = qemu_new_clock(QEMU_CLOCK_VIRTUAL);
    host_clock = qemu_new_clock(QEMU_CLOCK_HOST);
}

void libcpu_run_all_timers(void) {
    /* vm time timers */
    libcpu_run_timers(vm_clock);
    libcpu_run_timers(rt_clock);
    libcpu_run_timers(host_clock);
}

/***********************************************************/
/* real time host monotonic timer */

int use_rt_clock;

static void __attribute__((constructor)) init_get_clock(void) {
    use_rt_clock = 0;
#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 500000) || defined(__DragonFly__) || \
    defined(__FreeBSD_kernel__) || defined(__OpenBSD__)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            use_rt_clock = 1;
        }
    }
#endif
}

/* TSC handling */
uint64_t g_clock_start;
uint64_t g_clock_offset;

uint64_t cpu_get_tsc(void) {
    return cpu_get_real_ticks() - g_clock_offset + g_clock_start;
}
