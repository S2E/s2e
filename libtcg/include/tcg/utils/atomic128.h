/*
 * Simple interface for 128-bit atomic operations.
 *
 * Copyright (C) 2018 Linaro, Ltd.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * See docs/devel/atomics.rst for discussion about the guarantees each
 * atomic primitive is meant to provide.
 */

#ifndef QEMU_ATOMIC128_H
#define QEMU_ATOMIC128_H

#include "tcg/utils/int128.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * If __alignof(unsigned __int128) < 16, GCC may refuse to inline atomics
 * that are supported by the host, e.g. s390x.  We can force the pointer to
 * have our known alignment with __builtin_assume_aligned, however prior to
 * GCC 13 that was only reliable with optimization enabled.  See
 *   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=107389
 */
#if defined(CONFIG_ATOMIC128_OPT)
#if !defined(__OPTIMIZE__)
#define ATTRIBUTE_ATOMIC128_OPT __attribute__((optimize("O1")))
#endif
#define CONFIG_ATOMIC128
#endif
#ifndef ATTRIBUTE_ATOMIC128_OPT
#define ATTRIBUTE_ATOMIC128_OPT
#endif

/*
 * GCC is a house divided about supporting large atomic operations.
 *
 * For hosts that only have large compare-and-swap, a legalistic reading
 * of the C++ standard means that one cannot implement __atomic_read on
 * read-only memory, and thus all atomic operations must synchronize
 * through libatomic.
 *
 * See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80878
 *
 * This interpretation is not especially helpful for QEMU.
 * For softmmu, all RAM is always read/write from the hypervisor.
 * For user-only, if the guest doesn't implement such an __atomic_read
 * then the host need not worry about it either.
 *
 * Moreover, using libatomic is not an option, because its interface is
 * built for std::atomic<T>, and requires that *all* accesses to such an
 * object go through the library.  In our case we do not have an object
 * in the C/C++ sense, but a view of memory as seen by the guest.
 * The guest may issue a large atomic operation and then access those
 * pieces using word-sized accesses.  From the hypervisor, we have no
 * way to connect those two actions.
 *
 * Therefore, special case each platform.
 */

#include "tcg/utils/host/generic/atomic128-cas.h"
#include "tcg/utils/host/x86_64/atomic128-ldst.h"

#ifdef __cplusplus
}
#endif

#endif /* QEMU_ATOMIC128_H */
