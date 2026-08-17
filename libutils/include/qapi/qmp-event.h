/*
 * QMP Event related
 *
 * Copyright (c) 2014 Wenchao Xia
 *
 * Authors:
 *  Wenchao Xia   <wenchaoqemu@gmail.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QMP_EVENT_H
#define QMP_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

QDict *qmp_event_build_dict(const char *event_name);

#ifdef __cplusplus
}
#endif

#endif
