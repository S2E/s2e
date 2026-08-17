/*
 * Coroutines
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

#include <stdio.h>
#include <stdlib.h>

#include "coroutine-int.h"
#include "coroutine.h"

Coroutine *coroutine_create(CoroutineEntry *entry, uint64_t stack_size) {
    Coroutine *co = coroutine_new(stack_size);
    if (!co) {
        return NULL;
    }

    co->entry = entry;
    return co;
}

static void coroutine_swap(Coroutine *from, Coroutine *to) {
    CoroutineAction ret;

    ret = coroutine_switch(from, to, COROUTINE_YIELD);

    switch (ret) {
        case COROUTINE_YIELD:
            return;
        case COROUTINE_TERMINATE:
            coroutine_delete(to);
            return;
        default:
            abort();
    }
}

void coroutine_enter(Coroutine *co, void *opaque) {
    Coroutine *self = coroutine_self();

    if (co->caller) {
        fprintf(stderr, "Co-routine re-entered recursively\n");
        abort();
    }

    co->caller = self;
    co->entry_arg = opaque;
    coroutine_swap(self, co);
}

void coroutine_fn coroutine_yield(void) {
    Coroutine *self = coroutine_self();
    Coroutine *to = self->caller;

    if (!to) {
        fprintf(stderr, "Co-routine is yielding to no one\n");
        abort();
    }

    self->caller = NULL;
    coroutine_swap(self, to);
}
