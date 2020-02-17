///
/// Copyright (C) 2016, Cyberhaven
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
