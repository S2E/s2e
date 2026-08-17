/*
 * QNull
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Authors:
 *  Markus Armbruster <armbru@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1
 * or later.  See the COPYING.LIB file in the top-level directory.
 */

#ifndef QNULL_H
#define QNULL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "qapi/qmp/qobject.h"

typedef struct QNull {
    struct QObjectBase_ base;
} QNull;

extern QNull qnull_;

static inline QNull *qnull(void) {
    return qobject_ref(&qnull_);
}

void qnull_unref(QNull *q);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(QNull, qnull_unref)

#ifdef __cplusplus
}
#endif

#endif /* QNULL_H */
