/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2019 Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef __LIST_H__

#define __LIST_H__

#include <inttypes.h>

typedef struct list_entry_t {
    struct list_entry_t *prev;
    struct list_entry_t *next;
} list_entry_t;

static inline void list_init_head(list_entry_t *head) {
    head->prev = head;
    head->next = head;
}

static inline void list_add_tail(list_entry_t *head, list_entry_t *entry) {
    list_entry_t *prev = head->prev;

    entry->next = head;
    entry->prev = prev;
    prev->next = entry;
    head->prev = entry;
}

static inline list_entry_t *list_remove_tail(list_entry_t *head) {
    list_entry_t *prev;
    list_entry_t *entry;

    entry = head->prev;
    prev = entry->prev;
    head->prev = prev;
    prev->next = head;
    return entry;
}

static inline int list_empty(list_entry_t *head) {
    return head->next == head;
}

#define CONTAINING_RECORD(address, type, field) ((type *) ((uintptr_t) (address) - (uintptr_t) (&((type *) 0)->field)))

#endif
