/*
 * QEMU breakpoint & watchpoint definitions
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef EXEC_BREAKPOINT_H
#define EXEC_BREAKPOINT_H

#include <cpu/exec/memattrs.h>
#include <qqueue.h>
#include <tcg/exec/vaddr.h>

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
/* 0x08 currently unused */
#define BP_GDB                  0x10
#define BP_CPU                  0x20
#define BP_ANY                  (BP_GDB | BP_CPU)
#define BP_HIT_SHIFT            6
#define BP_WATCHPOINT_HIT_READ  (BP_MEM_READ << BP_HIT_SHIFT)
#define BP_WATCHPOINT_HIT_WRITE (BP_MEM_WRITE << BP_HIT_SHIFT)
#define BP_WATCHPOINT_HIT       (BP_MEM_ACCESS << BP_HIT_SHIFT)

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

/* S2E: C++ does not allow a member named vaddr to be declared with the type
   vaddr, because the declaration changes the meaning of the name inside
   the struct. The members use this alias so that C++ code can include this
   header without errors. */
typedef vaddr cpu_watchpoint_vaddr;

typedef struct CPUWatchpoint {
    cpu_watchpoint_vaddr vaddr;
    cpu_watchpoint_vaddr len;
    cpu_watchpoint_vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
} CPUWatchpoint;

#endif
