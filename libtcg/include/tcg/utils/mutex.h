// Copyright (c) 2019 Cyberhaven
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef _TCG_MUTEX_H_

#define _TCG_MUTEX_H_

#include <pthread.h>

typedef struct _mutex_t {
    pthread_mutex_t mutex;
} mutex_t;

static inline void mutex_init(mutex_t *m) {
    int ret = pthread_mutex_init(&m->mutex, NULL);
    if (ret < 0) {
        abort();
    }
}

static inline void mutex_lock(mutex_t *m) {
    pthread_mutex_lock(&m->mutex);
}

static inline void mutex_unlock(mutex_t *m) {
    pthread_mutex_unlock(&m->mutex);
}

#endif
