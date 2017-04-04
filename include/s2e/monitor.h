///
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __S2E_MONITOR_H__

#define __S2E_MONITOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include "qdict.h"

struct Monitor;
typedef struct Monitor Monitor;

///
/// \brief monitor_init connects to a qmp server
///
/// The S2E_QMP_SERVER environment variable contains
/// the server:port to connect to.
///
int monitor_init(void);

void monitor_close(void);

void monitor_emit_json(QObject *object);

int monitor_ready(void);

int monitor_cur_is_qmp(void);

void monitor_printf(Monitor *mon, const char *fmt, ...);
void monitor_vprintf(Monitor *mon, const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

#endif
