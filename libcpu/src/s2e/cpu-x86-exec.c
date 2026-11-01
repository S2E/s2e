/// Copyright (C) 2026  Vitaly Chipounov
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

/// @file
/// The entry point through which libs2e runs the CPU.
///
/// cpu_exec() runs the CPU loop and returns when the loop exits, as upstream's
/// does. cpu_x86_exec() does what upstream's callers of cpu_exec() do around
/// the call, and also handles a halt that happens while an interrupt is
/// already pending.

#include <cpu/config.h>
#include "cpu.h"
#include "exec-all.h"

#include <cpu/accel/cpu-loop.h>

int cpu_x86_exec(CPUX86State *env) {
    CPUState *cpu = env_cpu(env);
    int ret;

    libcpu_log_mask(CPU_LOG_EXEC, "cpu_loop enter mflags=%#lx hf1=%#x hf2=%#x\n", (uint64_t) env->mflags, env->hflags,
                    env->hflags2);

    for (;;) {
        // cpu_exec() delivers any exception_index that is not negative. The
        // previous call may have left a value there.
        cpu->exception_index = -1;
        ret = cpu_exec(cpu);

        // When the guest halts with an interrupt already pending, keep running
        // so that the interrupt is delivered without a round trip through the
        // KVM client. This also wakes up the CPU for an interrupt that IF masks.
        if (ret != EXCP_HLT || !cpu->interrupt_request) {
            break;
        }
        cpu->halted = 0;
    }

    // A pending exit request asked for a return to libs2e, and that return is
    // happening now. Clearing the request any earlier would lose a request made
    // during the first cpu_exec() call, since the guest keeps running after the
    // halt retry above.
    cpu->exit_request = 0;

    libcpu_log_mask(CPU_LOG_EXEC, "cpu_loop exit ret=%#x eip=%#lx\n", ret, (uint64_t) env->eip);
    return ret;
}
