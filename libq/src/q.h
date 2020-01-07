/*
 * Copyright 2016 - Cyberhaven
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef _Q_H_
#define _Q_H_

#include <inttypes.h>

#define container_of(addr, type, field) ((type *) ((uintptr_t)(addr) - (uintptr_t)(&((type *) 0)->field)))

#endif
