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
/// Maps the QEMU 1.0 guest memory accessors onto the accessors of
/// cpu/accel/cpu-ldst.h.
///
/// The QEMU 1.0 helpers (target-i386/op_helper.c) and translator
/// (target-i386/translate.c) call per-mode functions such as
/// cpu_ldl_kernel(), the ldl() shorthands, and cpu_ldub_code(). The softmmu
/// behind them is now upstream's cputlb.c, which has one function per access
/// size and takes the MMU index as an argument. This header keeps the old
/// names so that the old callers do not have to be edited before the 11.1
/// frontend replaces them. It goes away with them.
///
/// Every accessor passes a return address of 0. This tells the softmmu that
/// the caller is not generated code: a fault does not restore the CPU state
/// from a translation block, and symbolic data is concretized instead of
/// triggering a switch to symbolic execution.

#ifndef S2E_SOFTMMU_COMPAT_H
#define S2E_SOFTMMU_COMPAT_H

#include <cpu/accel/cpu-ldst.h>

/* MMU index of kernel mode, see x86_mmu_index(). */
#define SOFTMMU_COMPAT_KERNEL_IDX 0

/*
 * Kernel-mode accessors.
 */

static inline uint32_t cpu_ldub_kernel(CPUArchState *env, target_ulong ptr) {
    return cpu_ldub_mmuidx_ra(env, ptr, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline uint32_t cpu_lduw_kernel(CPUArchState *env, target_ulong ptr) {
    return cpu_lduw_mmuidx_ra(env, ptr, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline uint32_t cpu_ldl_kernel(CPUArchState *env, target_ulong ptr) {
    return cpu_ldl_mmuidx_ra(env, ptr, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline uint64_t cpu_ldq_kernel(CPUArchState *env, target_ulong ptr) {
    return cpu_ldq_mmuidx_ra(env, ptr, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline void cpu_stb_kernel(CPUArchState *env, target_ulong ptr, uint32_t v) {
    cpu_stb_mmuidx_ra(env, ptr, v, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline void cpu_stw_kernel(CPUArchState *env, target_ulong ptr, uint32_t v) {
    cpu_stw_mmuidx_ra(env, ptr, v, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline void cpu_stl_kernel(CPUArchState *env, target_ulong ptr, uint32_t v) {
    cpu_stl_mmuidx_ra(env, ptr, v, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

static inline void cpu_stq_kernel(CPUArchState *env, target_ulong ptr, uint64_t v) {
    cpu_stq_mmuidx_ra(env, ptr, v, SOFTMMU_COMPAT_KERNEL_IDX, 0);
}

/*
 * Code accessors, used by the translator.
 */

static inline MemOpIdx softmmu_compat_code_oi(CPUArchState *env, MemOp op) {
    return make_memop_idx(op, cpu_mmu_index(env_cpu(env), true));
}

static inline uint32_t cpu_ldub_code(CPUArchState *env, target_ulong ptr) {
    return cpu_ldb_code_mmu(env, ptr, softmmu_compat_code_oi(env, MO_UB), 0);
}

static inline uint32_t cpu_lduw_code(CPUArchState *env, target_ulong ptr) {
    return cpu_ldw_code_mmu(env, ptr, softmmu_compat_code_oi(env, MO_TEUW), 0);
}

static inline int cpu_ldsw_code(CPUArchState *env, target_ulong ptr) {
    return (int16_t) cpu_lduw_code(env, ptr);
}

static inline uint32_t cpu_ldl_code(CPUArchState *env, target_ulong ptr) {
    return cpu_ldl_code_mmu(env, ptr, softmmu_compat_code_oi(env, MO_TEUL), 0);
}

static inline uint64_t cpu_ldq_code(CPUArchState *env, target_ulong ptr) {
    return cpu_ldq_code_mmu(env, ptr, softmmu_compat_code_oi(env, MO_TEUQ), 0);
}

/*
 * Shorthands of the helpers. They use the global env and the MMU index of
 * the current privilege level.
 */

#define ldub(p) cpu_ldub_data(env, p)
#define ldsb(p) cpu_ldsb_data(env, p)
#define lduw(p) cpu_lduw_data(env, p)
#define ldsw(p) cpu_ldsw_data(env, p)
#define ldl(p)  cpu_ldl_data(env, p)
#define ldq(p)  cpu_ldq_data(env, p)

#define stb(p, v) cpu_stb_data(env, p, v)
#define stw(p, v) cpu_stw_data(env, p, v)
#define stl(p, v) cpu_stl_data(env, p, v)
#define stq(p, v) cpu_stq_data(env, p, v)

#endif
