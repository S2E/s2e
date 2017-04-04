///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_FASTREG_H
#define S2E_FASTREG_H

#include <s2e/S2EExecutionState.h>
#include <s2e/cpu.h>

#include <s2e/s2e_libcpu.h>

template <typename T> T s2e_read_register_concrete_fast(unsigned offset) {
    extern CPUArchState *env;
    if (likely(g_s2e_fast_concrete_invocation)) {
        return *(T *) ((uint8_t *) env + offset);
    } else {
        return g_s2e_state->regs()->read<T>(offset);
    }
}

#endif
