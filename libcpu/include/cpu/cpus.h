/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
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

#ifndef QEMU_CPUS_H
#define QEMU_CPUS_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

void qemu_init_cpu_loop(void);
void resume_all_vcpus(void);
void pause_all_vcpus(void);
void cpu_stop_current(void);

void cpu_synchronize_all_post_reset(void);
void cpu_synchronize_all_post_init(void);

typedef struct TimersState {
    int64_t cpu_ticks_prev;
    int64_t cpu_ticks_offset;
    int64_t cpu_clock_offset;
    int32_t cpu_ticks_enabled;
    int64_t dummy;

    /* slow down vm clock by a factor x. This is shared with QEMU over the libs2e interface */
    int32_t cpu_clock_scale_factor;

    int64_t cpu_clock_prev;
    int64_t cpu_clock_prev_scaled;
} TimersState;

extern TimersState timers_state;

/*
 * Called from S2EExecutor to scale down the clock when performing symbolic
 * execution.
 */
void cpu_enable_scaling(int scale);

#ifdef __cplusplus
}
#endif

#endif
