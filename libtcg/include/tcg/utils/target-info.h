/*
 * QEMU target info API (returning native types)
 *
 *  Copyright (c) Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_TARGET_INFO_H
#define QEMU_TARGET_INFO_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * target_name:
 *
 * Returns: Canonical target name (i.e. "i386").
 */
const char *target_name(void);

/**
 * target_long_bits:
 *
 * Returns: number of bits in a long type for this target (i.e. 64).
 */
unsigned target_long_bits(void);

/**
 * target_machine_typename:
 *
 * Returns: Name of the QOM interface implemented by machines
 *          usable on this target binary.
 */
const char *target_machine_typename(void);

/**
 * target_cpu_type:
 *
 * Returns: target CPU base QOM type name (i.e. TYPE_X86_CPU).
 */
const char *target_cpu_type(void);

/**
 * target_big_endian:
 *
 * Returns: %true if the (default) endianness of the target is big endian,
 *          %false otherwise.
 *
 * Common code should normally never need to know about the endianness of
 * the target, so please do *not* use this function unless you  know very
 * well what you are doing!
 */
bool target_big_endian(void);

/**
 * target_base_arm:
 *
 * Returns whether the target architecture is ARM or Aarch64.
 */
bool target_base_arm(void);

/**
 * target_arm:
 *
 * Returns whether the target architecture is ARM (32-bit, not Aarch64).
 */
bool target_arm(void);

/**
 * target_aarch64:
 *
 * Returns whether the target architecture is Aarch64.
 */
bool target_aarch64(void);

/**
 * target_base_ppc:
 *
 * Returns whether the target architecture is PowerPC 32-bit or 64-bit.
 */
bool target_base_ppc(void);

/**
 * target_ppc:
 *
 * Returns whether the target architecture is PowerPC 32-bit.
 */
bool target_ppc(void);

/**
 * target_ppc64:
 *
 * Returns whether the target architecture is PowerPC 64-bit.
 */
bool target_ppc64(void);

/**
 * target_s390x:
 *
 * Returns whether the target architecture is S390x.
 */
bool target_s390x(void);

/**
 * target_riscv64:
 *
 * Returns whether the target architecture is riscv64
 */
bool target_riscv64(void);

#ifdef COMPILING_PER_TARGET
/* S2E has no runtime TargetInfo: every component is built per target. */
#ifndef TARGET_BIG_ENDIAN
#error "TARGET_BIG_ENDIAN must be defined (cpu/config-target.h or -D) before tcg/utils/target-info.h"
#endif
#define target_big_endian() (TARGET_BIG_ENDIAN)
#endif

#ifdef __cplusplus
}
#endif

#endif /* QEMU_TARGET_INFO_H */
