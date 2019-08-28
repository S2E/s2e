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

#ifndef TCG_ATOMIC_H
#define TCG_ATOMIC_H

#define atomic_read(p) __atomic_load_n(p, __ATOMIC_RELAXED)
#define atomic_set(p, i) __atomic_store_n(p, i, __ATOMIC_RELAXED)
#define atomic_fetch_inc(p) __atomic_fetch_add(p, 1, __ATOMIC_SEQ_CST)
#define atomic_or(p, n) ((void) __sync_fetch_and_or(p, n))
#define atomic_or_fetch(p, n) __atomic_or_fetch(p, n, __ATOMIC_SEQ_CST)
#define atomic_and(p, n) ((void) __atomic_fetch_and(p, n, __ATOMIC_SEQ_CST))
#define atomic_cmpxchg(p, old, new) __sync_val_compare_and_swap(p, old, new)

#endif
