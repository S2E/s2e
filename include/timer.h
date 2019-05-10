/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#ifndef LIBCPU_TIMER_H
#define LIBCPU_TIMER_H

#include <inttypes.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCALE_MS 1000000

typedef struct CPUTimer CPUTimer;
typedef struct CPUClock CPUClock;
typedef void CPUTimerCB(void *opaque);

/* The real time clock should be used only for stuff which does not
   change the virtual machine state, as it is run even if the virtual
   machine is stopped. The real time clock has a frequency of 1000
   Hz. */
extern CPUClock *rt_clock;

/* The virtual clock is only run during the emulation. It is stopped
   when the virtual machine is stopped. Virtual timers use a high
   precision clock, usually cpu cycles (use ticks_per_sec). */
extern CPUClock *vm_clock;

/* The host clock should be use for device models that emulate accurate
   real time sources. It will continue to run when the virtual machine
   is suspended, and it will reflect system time changes the host may
   undergo (e.g. due to NTP). The host clock has the same precision as
   the virtual clock. */
extern CPUClock *host_clock;

int64_t libcpu_get_clock_ns(CPUClock *clock);

CPUTimer *libcpu_new_timer(CPUClock *clock, int scale, CPUTimerCB *cb, void *opaque);
void libcpu_free_timer(CPUTimer *ts);
void libcpu_del_timer(CPUTimer *ts);
void libcpu_mod_timer_ns(CPUTimer *ts, int64_t expire_time);
void libcpu_mod_timer(CPUTimer *ts, int64_t expire_time);
int libcpu_timer_expired(CPUTimer *timer_head, int64_t current_time);

void libcpu_run_timers(CPUClock *clock);
void libcpu_run_all_timers(void);
void init_clocks(void);

int64_t cpu_get_ticks(void);
void cpu_enable_ticks(void);
void cpu_disable_ticks(void);

uint64_t cpu_get_tsc(void);
extern uint64_t g_clock_start;
extern uint64_t g_clock_offset;

static inline CPUTimer *libcpu_new_timer_ms(CPUClock *clock, CPUTimerCB *cb, void *opaque) {
    return libcpu_new_timer(clock, SCALE_MS, cb, opaque);
}

static inline int64_t libcpu_get_clock_ms(CPUClock *clock) {
    return libcpu_get_clock_ns(clock) / SCALE_MS;
}

static inline int64_t get_ticks_per_sec(void) {
    return 1000000000LL;
}

/* real time host monotonic timer */
static inline int64_t get_clock_realtime(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

extern int use_rt_clock;

static inline int64_t get_clock(void) {
#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 500000) || defined(__DragonFly__) || \
    defined(__FreeBSD_kernel__)
    if (use_rt_clock) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000LL + ts.tv_nsec;
    } else
#endif
    {
        /* XXX: using gettimeofday leads to problems if the date
           changes, so it should be avoided. */
        return get_clock_realtime();
    }
}

int64_t cpu_get_clock(void);

/*******************************************/
/* host CPU ticks (if available) */

static inline int64_t cpu_get_real_ticks(void) {
    uint32_t low, high;
    int64_t val;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}

#ifdef __cplusplus
}
#endif

#endif
