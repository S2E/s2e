/*
 * ucontext coroutine initialization code
 *
 * Copyright (C) 2006  Anthony Liguori <anthony@codemonkey.ws>
 * Copyright (C) 2011  Kevin Wolf <kwolf@redhat.com>
 * Copyright (C) 2016  Cyberhaven <vitaly@cyberhaven.io>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/* XXX Is there a nicer way to disable glibc's stack check for longjmp? */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <ucontext.h>
#include "coroutine-int.h"

#define container_of(addr, type, field) ((type *) ((uintptr_t) (addr) - (uintptr_t) (&((type *) 0)->field)))

#define DO_UPCAST(type, field, dev) container_of(dev, type, field)

typedef struct {
    Coroutine base;
    void *stack;
    uint64_t stack_size;
    jmp_buf env;
} CoroutineUContext;

/**
 * Per-thread coroutine bookkeeping
 */
typedef struct {
    /** Currently executing coroutine */
    Coroutine *current;

    /** The default coroutine */
    CoroutineUContext leader;
} CoroutineThreadState;

static pthread_key_t thread_state_key;

/*
 * va_args to makecontext() must be type 'int', so passing
 * the pointer we need may require several int args. This
 * union is a quick hack to let us do that
 */
union cc_arg {
    void *p;
    int i[2];
};

static CoroutineThreadState *coroutine_get_thread_state(void) {
    CoroutineThreadState *s = pthread_getspecific(thread_state_key);

    if (!s) {
        s = g_malloc0(sizeof(*s));
        s->current = &s->leader.base;
        pthread_setspecific(thread_state_key, s);
    }
    return s;
}

static void coroutine_thread_cleanup(void *opaque) {
    CoroutineThreadState *s = opaque;

    g_free(s);
}

static void __attribute__((constructor)) coroutine_init(void) {
    int ret;

    ret = pthread_key_create(&thread_state_key, coroutine_thread_cleanup);
    if (ret != 0) {
        fprintf(stderr, "unable to create leader key: %s\n", strerror(errno));
        abort();
    }
}

static void coroutine_trampoline(int i0, int i1) {
    union cc_arg arg;
    CoroutineUContext *self;
    Coroutine *co;

    arg.i[0] = i0;
    arg.i[1] = i1;
    self = arg.p;
    co = &self->base;

    /* Initialize longjmp environment and switch back the caller */
    if (!setjmp(self->env)) {
        longjmp(*(jmp_buf *) co->entry_arg, 1);
    }

    while (true) {
        co->entry(co->entry_arg);
        coroutine_switch(co, co->caller, COROUTINE_TERMINATE);
    }
}

static Coroutine *_coroutine_new(uint64_t stack_size) {
    CoroutineUContext *co;
    ucontext_t old_uc, uc;
    jmp_buf old_env;
    union cc_arg arg = {0};

    /* The ucontext functions preserve signal masks which incurs a system call
     * overhead.  setjmp()/longjmp() does not preserve signal masks but only
     * works on the current stack.  Since we need a way to create and switch to
     * a new stack, use the ucontext functions for that but setjmp()/longjmp()
     * for everything else.
     */

    if (getcontext(&uc) == -1) {
        abort();
    }

    co = g_malloc0(sizeof(*co));
    co->stack_size = stack_size;

    /* Don't allocate the stack on the heap in order to simplify debugging of potential
     * stack overflows.
     */
    co->stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
    if (co->stack == MAP_FAILED) {
        g_free(co);
        return NULL;
    }

    co->base.entry_arg = &old_env; /* stash away our jmp_buf */

    uc.uc_link = &old_uc;
    uc.uc_stack.ss_sp = co->stack;
    uc.uc_stack.ss_size = stack_size;
    uc.uc_stack.ss_flags = 0;

    arg.p = co;

    makecontext(&uc, (void (*)(void)) coroutine_trampoline, 2, arg.i[0], arg.i[1]);

    /* swapcontext() in, longjmp() back out */
    if (!setjmp(old_env)) {
        swapcontext(&old_uc, &uc);
    }
    return &co->base;
}

Coroutine *coroutine_new(uint64_t stack_size) {
    return _coroutine_new(stack_size);
}

void coroutine_delete(Coroutine *co_) {
    CoroutineUContext *co = DO_UPCAST(CoroutineUContext, base, co_);
    munmap(co->stack, co->stack_size);
    g_free(co);
}

CoroutineAction coroutine_switch(Coroutine *from_, Coroutine *to_, CoroutineAction action) {
    CoroutineUContext *from = DO_UPCAST(CoroutineUContext, base, from_);
    CoroutineUContext *to = DO_UPCAST(CoroutineUContext, base, to_);
    CoroutineThreadState *s = coroutine_get_thread_state();
    int ret;

    s->current = to_;

    ret = setjmp(from->env);
    if (ret == 0) {
        longjmp(to->env, action);
    }
    return ret;
}

Coroutine *coroutine_self(void) {
    CoroutineThreadState *s = coroutine_get_thread_state();

    return s->current;
}

bool in_coroutine(void) {
    CoroutineThreadState *s = pthread_getspecific(thread_state_key);

    return s && s->current->caller;
}
