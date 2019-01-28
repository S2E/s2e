/*
 * Coroutine implementation
 *
 * Copyright IBM, Corp. 2011
 * Copyright 2016 - Cyberhaven
 *
 * Authors:
 *  Stefan Hajnoczi    <stefanha@linux.vnet.ibm.com>
 *  Kevin Wolf         <kwolf@redhat.com>
 *  Vitaly Chipounov   <vitaly@cyberhaven.io>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef COROUTINE_H
#define COROUTINE_H

#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Coroutines are a mechanism for stack switching and can be used for
 * cooperative userspace threading.  These functions provide a simple but
 * useful flavor of coroutines that is suitable for writing sequential code,
 * rather than callbacks, for operations that need to give up control while
 * waiting for events to complete.
 *
 * These functions are re-entrant and may be used outside the global mutex.
 */

/**
 * Mark a function that executes in coroutine context
 *
 * Functions that execute in coroutine context cannot be called directly from
 * normal functions.  In the future it would be nice to enable compiler or
 * static checker support for catching such errors.  This annotation might make
 * it possible and in the meantime it serves as documentation.
 *
 * For example:
 *
 *   static void coroutine_fn foo(void) {
 *       ....
 *   }
 */
#define coroutine_fn

typedef struct Coroutine Coroutine;

/**
 * Coroutine entry point
 *
 * When the coroutine is entered for the first time, opaque is passed in as an
 * argument.
 *
 * When this function returns, the coroutine is destroyed automatically and
 * execution continues in the caller who last entered the coroutine.
 */
typedef void coroutine_fn CoroutineEntry(void *opaque);

/**
 * Create a new coroutine
 *
 * Use coroutine_enter() to actually transfer control to the coroutine.
 */
Coroutine *coroutine_create(CoroutineEntry *entry, uint64_t stack_size);

/**
 * Transfer control to a coroutine
 *
 * The opaque argument is passed as the argument to the entry point when
 * entering the coroutine for the first time.  It is subsequently ignored.
 */
void coroutine_enter(Coroutine *coroutine, void *opaque);

/**
 * Transfer control back to a coroutine's caller
 *
 * This function does not return until the coroutine is re-entered using
 * coroutine_enter().
 */
void coroutine_fn coroutine_yield(void);

/**
 * Get the currently executing coroutine
 */
Coroutine *coroutine_fn coroutine_self(void);

/**
 * Return whether or not currently inside a coroutine
 *
 * This can be used to write functions that work both when in coroutine context
 * and when not in coroutine context.  Note that such functions cannot use the
 * coroutine_fn annotation since they work outside coroutine context.
 */
bool in_coroutine(void);

#ifdef __cplusplus
}
#endif

#endif /* COROUTINE_H */
